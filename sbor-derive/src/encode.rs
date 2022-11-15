use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::*;

use crate::utils::*;

macro_rules! trace {
    ($($arg:expr),*) => {{
        #[cfg(feature = "trace")]
        println!($($arg),*);
    }};
}

pub fn handle_encode(input: TokenStream) -> Result<TokenStream> {
    trace!("handle_encode() starts");

    let DeriveInput {
        attrs,
        ident,
        data,
        generics,
        ..
    } = parse2(input)?;
    let custom_type_id = custom_type_id(&attrs);
    let (impl_generics, ty_generics, where_clause, sbor_cti) =
        build_generics(&generics, custom_type_id)?;

    let output = match data {
        Data::Struct(s) => match s.fields {
            syn::Fields::Named(FieldsNamed { named, .. }) => {
                // ns: not skipped
                let ns: Vec<&Field> = named.iter().filter(|f| !is_encoding_skipped(f)).collect();
                let ns_ids = ns.iter().map(|f| &f.ident);
                let ns_len = Index::from(ns_ids.len());
                quote! {
                    impl #impl_generics ::sbor::Encode <#sbor_cti> for #ident #ty_generics #where_clause {
                        #[inline]
                        fn encode_type_id(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            encoder.write_type_id(::sbor::type_id::SborTypeId::Struct);
                        }
                        #[inline]
                        fn encode_value(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            use ::sbor::{self, Encode};
                            encoder.write_size(#ns_len);
                            #(self.#ns_ids.encode(encoder);)*
                        }
                    }
                }
            }
            syn::Fields::Unnamed(FieldsUnnamed { unnamed, .. }) => {
                let mut ns_indices = Vec::new();
                for (i, f) in unnamed.iter().enumerate() {
                    if !is_encoding_skipped(f) {
                        ns_indices.push(Index::from(i));
                    }
                }
                let ns_len = Index::from(ns_indices.len());
                quote! {
                    impl #impl_generics ::sbor::Encode <#sbor_cti> for #ident #ty_generics #where_clause {
                        #[inline]
                        fn encode_type_id(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            encoder.write_type_id(::sbor::type_id::SborTypeId::Struct);
                        }
                        #[inline]
                        fn encode_value(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            use ::sbor::{self, Encode};
                            encoder.write_size(#ns_len);
                            #(self.#ns_indices.encode(encoder);)*
                        }
                    }
                }
            }
            syn::Fields::Unit => {
                quote! {
                    impl #impl_generics ::sbor::Encode <#sbor_cti> for #ident #ty_generics #where_clause {
                        #[inline]
                        fn encode_type_id(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            encoder.write_type_id(::sbor::type_id::SborTypeId::Struct);
                        }
                        #[inline]
                        fn encode_value(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            encoder.write_size(0);
                        }
                    }
                }
            }
        },
        Data::Enum(DataEnum { variants, .. }) => {
            let match_arms = variants.iter().map(|v| {
                let v_id = &v.ident;
                let discriminator_string = v_id.to_string();
                let discriminator: Expr = parse_quote! { #discriminator_string };

                match &v.fields {
                    syn::Fields::Named(FieldsNamed { named, .. }) => {
                        let ns: Vec<&Field> =
                            named.iter().filter(|f| !is_encoding_skipped(f)).collect();
                        let ns_ids = ns.iter().map(|f| &f.ident);
                        let ns_ids2 = ns.iter().map(|f| &f.ident);
                        let ns_len = Index::from(ns.len());
                        quote! {
                            Self::#v_id {#(#ns_ids,)* ..} => {
                                encoder.write_discriminator(#discriminator);
                                encoder.write_size(#ns_len);
                                #(#ns_ids2.encode(encoder);)*
                            }
                        }
                    }
                    syn::Fields::Unnamed(FieldsUnnamed { unnamed, .. }) => {
                        let args = (0..unnamed.len()).map(|i| format_ident!("a{}", i));
                        let mut ns_args = Vec::<Ident>::new();
                        for (i, f) in unnamed.iter().enumerate() {
                            if !is_encoding_skipped(f) {
                                ns_args.push(format_ident!("a{}", i));
                            }
                        }
                        let ns_len = Index::from(ns_args.len());
                        quote! {
                            Self::#v_id (#(#args),*) => {
                                encoder.write_discriminator(#discriminator);
                                encoder.write_size(#ns_len);
                                #(#ns_args.encode(encoder);)*
                            }
                        }
                    }
                    syn::Fields::Unit => {
                        quote! {
                            Self::#v_id => {
                                encoder.write_discriminator(#discriminator);
                                encoder.write_size(0);
                            }
                        }
                    }
                }
            });

            if match_arms.len() == 0 {
                quote! {
                    impl #impl_generics ::sbor::Encode <#sbor_cti> for #ident #ty_generics #where_clause {
                        #[inline]
                        fn encode_type_id(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            encoder.write_type_id(::sbor::type_id::SborTypeId::Enum);
                        }
                        #[inline]
                        fn encode_value(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                        }
                    }
                }
            } else {
                quote! {
                    impl #impl_generics ::sbor::Encode <#sbor_cti> for #ident #ty_generics #where_clause {
                        #[inline]
                        fn encode_type_id(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            encoder.write_type_id(::sbor::type_id::SborTypeId::Enum);
                        }
                        #[inline]
                        fn encode_value(&self, encoder: &mut ::sbor::Encoder <#sbor_cti>) {
                            use ::sbor::{self, Encode};

                            match self {
                                #(#match_arms)*
                            }
                        }
                    }
                }
            }
        }
        Data::Union(_) => {
            return Err(Error::new(Span::call_site(), "Union is not supported!"));
        }
    };

    #[cfg(feature = "trace")]
    crate::utils::print_generated_code("Encode", &output);

    trace!("handle_encode() finishes");
    Ok(output)
}

#[cfg(test)]
mod tests {
    use proc_macro2::TokenStream;
    use std::str::FromStr;

    use super::*;

    fn assert_code_eq(a: TokenStream, b: TokenStream) {
        assert_eq!(a.to_string(), b.to_string());
    }

    #[test]
    fn test_encode_struct() {
        let input = TokenStream::from_str("struct Test {a: u32}").unwrap();
        let output = handle_encode(input).unwrap();

        assert_code_eq(
            output,
            quote! {
                impl <CTI: ::sbor::type_id::CustomTypeId> ::sbor::Encode<CTI> for Test {
                    #[inline]
                    fn encode_type_id(&self, encoder: &mut ::sbor::Encoder<CTI>) {
                        encoder.write_type_id(::sbor::type_id::SborTypeId::Struct);
                    }
                    #[inline]
                    fn encode_value(&self, encoder: &mut ::sbor::Encoder<CTI>) {
                        use ::sbor::{self, Encode};
                        encoder.write_size(1);
                        self.a.encode(encoder);
                    }
                }
            },
        );
    }

    #[test]
    fn test_encode_enum() {
        let input = TokenStream::from_str("enum Test {A, B (u32), C {x: u8}}").unwrap();
        let output = handle_encode(input).unwrap();

        assert_code_eq(
            output,
            quote! {
                impl <CTI: ::sbor::type_id::CustomTypeId> ::sbor::Encode<CTI> for Test {
                    #[inline]
                    fn encode_type_id(&self, encoder: &mut ::sbor::Encoder<CTI>) {
                        encoder.write_type_id(::sbor::type_id::SborTypeId::Enum);
                    }
                    #[inline]
                    fn encode_value(&self, encoder: &mut ::sbor::Encoder<CTI>) {
                        use ::sbor::{self, Encode};
                        match self {
                            Self::A => {
                                encoder.write_discriminator("A");
                                encoder.write_size(0);
                            }
                            Self::B(a0) => {
                                encoder.write_discriminator("B");
                                encoder.write_size(1);
                                a0.encode(encoder);
                            }
                            Self::C { x, .. } => {
                                encoder.write_discriminator("C");
                                encoder.write_size(1);
                                x.encode(encoder);
                            }
                        }
                    }
                }
            },
        );
    }

    #[test]
    fn test_skip() {
        let input = TokenStream::from_str("struct Test {#[sbor(skip)] a: u32}").unwrap();
        let output = handle_encode(input).unwrap();

        assert_code_eq(
            output,
            quote! {
                impl <CTI: ::sbor::type_id::CustomTypeId> ::sbor::Encode<CTI> for Test {
                    #[inline]
                    fn encode_type_id(&self, encoder: &mut ::sbor::Encoder<CTI>) {
                        encoder.write_type_id(::sbor::type_id::SborTypeId::Struct);
                    }
                    #[inline]
                    fn encode_value(&self, encoder: &mut ::sbor::Encoder<CTI>) {
                        use ::sbor::{self, Encode};
                        encoder.write_size(0);
                    }
                }
            },
        );
    }

    #[test]
    fn test_custom_type_id() {
        let input = TokenStream::from_str(
            "#[sbor(custom_type_id = \"NoCustomTypeId\")] struct Test {#[sbor(skip)] a: u32}",
        )
        .unwrap();
        let output = handle_encode(input).unwrap();

        assert_code_eq(
            output,
            quote! {
                impl ::sbor::Encode<NoCustomTypeId> for Test {
                    #[inline]
                    fn encode_type_id(&self, encoder: &mut ::sbor::Encoder<NoCustomTypeId>) {
                        encoder.write_type_id(::sbor::type_id::SborTypeId::Struct);
                    }
                    #[inline]
                    fn encode_value(&self, encoder: &mut ::sbor::Encoder<NoCustomTypeId>) {
                        use ::sbor::{self, Encode};
                        encoder.write_size(0);
                    }
                }
            },
        );
    }

    #[test]
    fn test_custom_type_id_canonical_path() {
        let input = TokenStream::from_str(
            "#[sbor(custom_type_id = \"::sbor::basic::NoCustomTypeId\")] struct Test {#[sbor(skip)] a: u32}",
        )
        .unwrap();
        let output = handle_encode(input).unwrap();

        assert_code_eq(
            output,
            quote! {
                impl ::sbor::Encode<::sbor::basic::NoCustomTypeId> for Test {
                    #[inline]
                    fn encode_type_id(&self, encoder: &mut ::sbor::Encoder<::sbor::basic::NoCustomTypeId>) {
                        encoder.write_type_id(::sbor::type_id::SborTypeId::Struct);
                    }
                    #[inline]
                    fn encode_value(&self, encoder: &mut ::sbor::Encoder<::sbor::basic::NoCustomTypeId>) {
                        use ::sbor::{self, Encode};
                        encoder.write_size(0);
                    }
                }
            },
        );
    }
}
