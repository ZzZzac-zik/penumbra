use proc_macro::TokenStream;
use quote::quote;
use syn::{Attribute, DeriveInput, Ident, LitInt, parse_macro_input};

struct Opts {
    order: Ident,
    size: Option<LitInt>,
}

fn opts(attrs: &[Attribute]) -> Result<Opts, syn::Error> {
    let mut opts = Opts { order: Ident::new("LE", proc_macro2::Span::call_site()), size: None };

    for attr in attrs {
        if !attr.path().is_ident("bytes") {
            continue;
        }

        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("order") {
                let value: Ident = meta.value()?.parse()?;

                return match value.to_string().as_str() {
                    "LE" | "BE" => {
                        opts.order = value;

                        Ok(())
                    }
                    _ => Err(syn::Error::new_spanned(&value, "expected `LE` or `BE`")),
                };
            }

            if meta.path.is_ident("size") {
                opts.size = Some(meta.value()?.parse()?);

                return Ok(());
            }

            Err(meta.error("unknown `bytes` option, expected `order` or `size`"))
        })?;
    }

    Ok(opts)
}

pub fn derive_to_bytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let Opts { order, size } = match opts(&input.attrs) {
        Ok(opts) => opts,
        Err(e) => return e.to_compile_error().into(),
    };

    let size = size.map_or_else(|| quote!(size_of::<Self>()), |size| quote!(#size));
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics crate::traits::ToBytes for #name #ty_generics #where_clause {
            const SIZE: usize = #size;
            type Output = [u8; #size];

            fn to_bytes(&self) -> Self::Output {
                let mut buf = [0u8; #size];
                wincode::config::serialize_into(&mut buf[..], self, crate::traits::#order).unwrap();
                buf
            }
        }
    };

    TokenStream::from(expanded)
}

pub fn derive_from_bytes(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let Opts { order, size } = match opts(&input.attrs) {
        Ok(opts) => opts,
        Err(e) => return e.to_compile_error().into(),
    };

    let size = size.map_or_else(|| quote!(size_of::<Self>()), |size| quote!(#size));
    let name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let expanded = quote! {
        impl #impl_generics crate::traits::FromBytes for #name #ty_generics #where_clause {
            const SIZE: usize = #size;

            fn from_bytes(raw: &[u8]) -> Option<Self> {
                if raw.len() < <Self as crate::traits::FromBytes>::SIZE {
                    return None;
                }

                wincode::config::deserialize(raw, crate::traits::#order).ok()
            }
        }
    };

    TokenStream::from(expanded)
}
