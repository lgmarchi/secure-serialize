use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::Parser, parse_macro_input, punctuated::Punctuated, Data, DeriveInput, Expr, Fields, Lit,
    Meta, Token,
};

/// Derives `SecureSerialize` for a struct.
///
/// Fields marked with `#[redact]` or `#[redact(with = "...")]` will be redacted when serialized.
///
/// # Attributes
///
/// - `#[redact]` — Redact with default `"<redacted>"`
/// - `#[redact(with = "***")]` — Redact with custom string `"***"`
///
/// # Example
///
/// ```ignore
/// #[derive(SecureSerialize, Deserialize)]
/// struct Config {
///     pub host: String,
///     #[redact]
///     pub api_key: String,
///     #[redact(with = "***")]
///     pub password: String,
/// }
/// ```
#[proc_macro_derive(SecureSerialize, attributes(redact))]
pub fn derive_secure_serialize(input: TokenStream) -> TokenStream {
    let DeriveInput {
        ident,
        data,
        generics,
        ..
    } = parse_macro_input!(input);

    let fields = match data {
        Data::Struct(s) => match s.fields {
            Fields::Named(f) => f.named,
            _ => {
                return syn::Error::new_spanned(
                    &ident,
                    "SecureSerialize only supports structs with named fields",
                )
                .to_compile_error()
                .into();
            }
        },
        _ => {
            return syn::Error::new_spanned(&ident, "SecureSerialize only supports structs")
                .to_compile_error()
                .into();
        }
    };

    // Separate fields into categories
    let mut redacted_fields: Vec<(syn::Ident, String, String)> = Vec::new(); // (ident, name, redaction_string)
    let mut redacted_custom_fields: Vec<(
        syn::Ident,
        String,
        String,
        proc_macro2::TokenStream,
        syn::Type,
    )> = Vec::new(); // (ident, name, redaction_string, serialize_path, type)
    let mut custom_serialize_fields: Vec<(syn::Ident, proc_macro2::TokenStream, syn::Type)> =
        Vec::new(); // (ident, serialize_path, type)
    let mut normal_field_names: Vec<syn::Ident> = Vec::new();

    for field in &fields {
        let name = field.ident.as_ref().expect("named field");
        let name_str = name.to_string();
        let field_type = field.ty.clone();

        // Check for #[redact] or #[redact(with = "...")]
        let (is_redacted, redaction_string) = extract_redact_attribute(&field.attrs);

        // Extract custom serialize_with function path
        let custom_serialize_path = extract_serialize_with_attribute(&field.attrs);

        match (is_redacted, &custom_serialize_path) {
            (true, Some(path)) => redacted_custom_fields.push((
                name.clone(),
                name_str,
                redaction_string,
                path.clone(),
                field_type,
            )),
            (true, None) => redacted_fields.push((name.clone(), name_str, redaction_string)),
            (false, Some(path)) => {
                custom_serialize_fields.push((name.clone(), path.clone(), field_type))
            }
            (false, None) => {
                normal_field_names.push(name.clone());
            }
        }
    }

    let (impl_generics, ty_generics, where_clause) = generics.split_for_impl();

    // Extract names and idents for code generation
    let redacted_field_names: Vec<String> =
        redacted_fields.iter().map(|(_, n, _)| n.clone()).collect();
    let redacted_field_idents: Vec<syn::Ident> =
        redacted_fields.iter().map(|(i, _, _)| i.clone()).collect();
    let redaction_strings: Vec<proc_macro2::TokenStream> = redacted_fields
        .iter()
        .map(|(_, _, r)| {
            r.parse::<proc_macro2::TokenStream>()
                .unwrap_or_else(|_| quote! { "<redacted>" })
        })
        .collect();

    let redacted_custom_field_names: Vec<String> = redacted_custom_fields
        .iter()
        .map(|(_, n, _, _, _)| n.clone())
        .collect();
    let redacted_custom_strings: Vec<proc_macro2::TokenStream> = redacted_custom_fields
        .iter()
        .map(|(_, _, r, _, _)| {
            r.parse::<proc_macro2::TokenStream>()
                .unwrap_or_else(|_| quote! { "<redacted>" })
        })
        .collect();

    let custom_serialize_idents: Vec<syn::Ident> = custom_serialize_fields
        .iter()
        .map(|(i, _, _)| i.clone())
        .collect();

    // Helper to generate wrapper for custom serialize_with
    let generate_wrapper = |field_ident: &syn::Ident,
                            path: &proc_macro2::TokenStream,
                            field_type: &syn::Type| {
        quote! {
            {
                struct _Wrapper<'a>(&'a #field_type);
                impl<'a> ::serde::Serialize for _Wrapper<'a>
                {
                    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
                    where
                        S: ::serde::Serializer,
                    {
                        #path(self.0, serializer)
                    }
                }
                _Wrapper(&self.#field_ident)
            }
        }
    };

    // Generate wrappers for custom serialize fields in impl Serialize
    let custom_field_wrappers: Vec<proc_macro2::TokenStream> = custom_serialize_fields
        .iter()
        .map(|(ident, path, ty)| generate_wrapper(ident, path, ty))
        .collect();

    // Generate wrappers for redacted_custom fields in to_json_unredacted
    let redacted_custom_json_wrappers: Vec<proc_macro2::TokenStream> = redacted_custom_fields
        .iter()
        .map(|(ident, _, _, path, ty)| {
            let wrapper = generate_wrapper(ident, path, ty);
            quote! { ::serde_json::to_value(#wrapper)? }
        })
        .collect();

    // Generate wrappers for custom_serialize fields in to_json_unredacted
    let custom_json_wrappers: Vec<proc_macro2::TokenStream> = custom_serialize_fields
        .iter()
        .map(|(ident, path, ty)| {
            let wrapper = generate_wrapper(ident, path, ty);
            quote! { ::serde_json::to_value(#wrapper)? }
        })
        .collect();

    let expanded = quote! {
        impl #impl_generics ::serde::Serialize for #ident #ty_generics #where_clause {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: ::serde::Serializer,
            {
                use ::serde::ser::SerializeStruct;
                let mut s = serializer.serialize_struct(
                    stringify!(#ident),
                    0usize
                    #(+ { let _ = stringify!(#redacted_field_names); 1usize })*
                    #(+ { let _ = stringify!(#redacted_custom_field_names); 1usize })*
                    #(+ { let _ = stringify!(#custom_serialize_idents); 1usize })*
                    #(+ { let _ = stringify!(#normal_field_names); 1usize })*
                )?;

                // Serialize redacted fields with their redaction strings
                #(s.serialize_field(#redacted_field_names, #redaction_strings)?;)*

                // Serialize redacted fields with custom serialize using their redaction strings
                #(s.serialize_field(#redacted_custom_field_names, #redacted_custom_strings)?;)*

                // Serialize non-secret fields with custom serializers
                #(s.serialize_field(stringify!(#custom_serialize_idents), &#custom_field_wrappers)?;)*

                // Serialize normal fields directly
                #(s.serialize_field(stringify!(#normal_field_names), &self.#normal_field_names)?;)*

                s.end()
            }
        }

        impl #impl_generics ::secure_serialize::SecureSerialize for #ident #ty_generics #where_clause {
            fn redacted_keys() -> &'static [&'static str] {
                &[#(#redacted_field_names,)* #(#redacted_custom_field_names,)*]
            }

            fn to_json_unredacted(&self) -> ::std::result::Result<::serde_json::Value, ::serde_json::Error> {
                use ::serde_json::Value as JsonValue;
                let mut result = ::serde_json::Map::new();

                // Redacted fields - use to_value for proper serialization
                #(result.insert(#redacted_field_names.to_string(), ::serde_json::to_value(&self.#redacted_field_idents)?);)*

                // Redacted fields with custom serialize - use custom serializer
                #(result.insert(#redacted_custom_field_names.to_string(), #redacted_custom_json_wrappers);)*

                // Custom serialize fields (non-redacted) - use custom serializer
                #(result.insert(stringify!(#custom_serialize_idents).to_string(), #custom_json_wrappers);)*

                // Normal fields
                #(result.insert(stringify!(#normal_field_names).to_string(), ::serde_json::to_value(&self.#normal_field_names)?);)*

                Ok(JsonValue::Object(result))
            }
        }
    };

    let tokens = expanded.into();
    // eprintln!("GENERATED TOKENS:\n{}", tokens);
    tokens
}

/// Extracts the `#[redact]` or `#[redact(with = "...")]` attribute from a field.
/// Returns `(true, redaction_string)` if found, `(false, _)` otherwise.
fn extract_redact_attribute(attrs: &[syn::Attribute]) -> (bool, String) {
    for attr in attrs {
        if !attr.path().is_ident("redact") {
            continue;
        }

        match &attr.meta {
            syn::Meta::Path(_) => {
                // #[redact] with no arguments
                return (true, "\"<redacted>\"".to_string());
            }
            syn::Meta::List(list) => {
                // #[redact(...)]
                if let Ok(Meta::NameValue(nv)) = list.parse_args::<Meta>().and_then(|m| match m {
                    Meta::NameValue(nv) if nv.path.is_ident("with") => Ok(Meta::NameValue(nv)),
                    _ => Err(syn::Error::new_spanned(
                        &list,
                        "redact attribute expects: #[redact(with = \"string\")]",
                    )),
                }) {
                    if let syn::Expr::Lit(expr_lit) = &nv.value {
                        if let syn::Lit::Str(lit_str) = &expr_lit.lit {
                            // Return the string literal with quotes preserved
                            return (true, format!("\"{}\"", lit_str.value()));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    (false, String::new())
}

/// Extracts the `serialize_with` path from `#[serde(...)]` attributes.
fn extract_serialize_with_attribute(attrs: &[syn::Attribute]) -> Option<proc_macro2::TokenStream> {
    for attr in attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }

        let Meta::List(list) = &attr.meta else {
            continue;
        };

        let metas = Punctuated::<Meta, Token![,]>::parse_terminated
            .parse2(list.tokens.clone())
            .ok()?;

        for meta in metas {
            let Meta::NameValue(name_value) = meta else {
                continue;
            };
            if !name_value.path.is_ident("serialize_with") {
                continue;
            }

            let Expr::Lit(expr_lit) = &name_value.value else {
                continue;
            };
            let Lit::Str(value) = &expr_lit.lit else {
                continue;
            };

            return value.parse::<proc_macro2::TokenStream>().ok();
        }
    }

    None
}
