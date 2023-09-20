use proc_macro::TokenStream;
use quote::quote;
use radix_engine_common::prelude::CheckedNeg;
use syn::{parse, spanned::Spanned, Error, Expr, Lit, Result, UnOp};

extern crate radix_engine_common;
use radix_engine_common::math::{Decimal, PreciseDecimal};

fn get_decimal_from_expr(expr: &Expr) -> Result<Decimal> {
    match expr {
        Expr::Lit(lit) => match &lit.lit {
            Lit::Str(lit_str) => Decimal::try_from(lit_str.value())
                .map_err(|err| Error::new(lit_str.span(), format!("Parsing failed due to {:?}", err.to_string()))),
            Lit::Int(lit_int) => Decimal::try_from(lit_int.base10_digits())
                .map_err(|err| Error::new(lit_int.span(),format!("Parsing failed due to {:?}", err.to_string()))),
            Lit::Bool(lit_bool) => Ok(Decimal::from(lit_bool.value)),
            other_lit => Err(Error::new(
                other_lit.span(),
                "Not supported literal. This macro only supports string, integer and bool literal expressions.",
            )),
        },
        Expr::Group(group) => get_decimal_from_expr(&group.expr),
        Expr::Unary(unary) => match unary.op {
            UnOp::Neg(unary_neg) => {
                let res = get_decimal_from_expr(unary.expr.as_ref());
                match res {
                    Ok(val) => {
                        let val = val.checked_neg().ok_or(Error::new(unary_neg.span, "Parsing failed due to Overflow"))?;
                        Ok(val)
                    },
                    Err(err) => Err(syn::Error::new(unary_neg.span, err.to_string())),
                }
            }
            other_unary => Err(Error::new(
                other_unary.span(),
                "Not supported unary operator. This macro only supports '-' unary operator.",
            )),
        },
        other_expr => Err(Error::new(
            other_expr.span(),
            "Not supported expression. This macro only supports string, integer and bool literal expressions.",
        )),
    }
}

fn get_precise_decimal_from_expr(expr: &Expr) -> Result<PreciseDecimal> {
    match expr {
        Expr::Lit(lit) => match &lit.lit {
            Lit::Str(lit_str) => PreciseDecimal::try_from(lit_str.value())
                .map_err(|err| Error::new(lit_str.span(), format!("Parsing failed due to {:?}", err.to_string()))),
            Lit::Int(lit_int) => PreciseDecimal::try_from(lit_int.base10_digits())
                .map_err(|err| Error::new(lit_int.span(), format!("Parsing failed due to {:?}", err.to_string()))),
            Lit::Bool(lit_bool) => Ok(PreciseDecimal::from(lit_bool.value)),
            other_lit => Err(Error::new(
                other_lit.span(),
                "Not supported literal. This macro only supports string, integer and bool literal expressions.",
            )),
        },
        Expr::Group(group) => get_precise_decimal_from_expr(&group.expr),
        Expr::Unary(unary) => match unary.op {
            UnOp::Neg(unary_neg) => {
                let res = get_precise_decimal_from_expr(unary.expr.as_ref());
                match res {
                    Ok(val) => {
                        let val = val.checked_neg().ok_or(Error::new(unary_neg.span, "Parsing failed due to Overflow"))?;
                        Ok(val)
                    },
                    Err(err) => Err(syn::Error::new(unary_neg.span, err.to_string())),
                }
            }
            other_unary => Err(Error::new(
                other_unary.span(),
                "Not supported unary operator. This macro only supports '-' unary operator.",
            )),
        },
        other_expr => Err(Error::new(
            other_expr.span(),
            "Not supported expression. This macro only supports string, integer and bool literal expressions.",
        )),
    }
}

pub fn to_decimal(input: TokenStream) -> Result<TokenStream> {
    // Parse the input into an Expression
    let expr = parse::<Expr>(input)?;

    let decimal = get_decimal_from_expr(&expr)?;
    let int = decimal.0;
    let arr = int.to_digits();
    let i0 = arr[0];
    let i1 = arr[1];
    let i2 = arr[2];

    Ok(TokenStream::from(quote! {
        radix_engine_common::math::Decimal(radix_engine_common::math::I192::from_digits([#i0, #i1, #i2]))
    }))
}

pub fn to_precise_decimal(input: TokenStream) -> Result<TokenStream> {
    // Parse the input into an Expression
    let expr = parse::<Expr>(input)?;

    let decimal = get_precise_decimal_from_expr(&expr)?;
    let int = decimal.0;
    let arr = int.to_digits();
    let i0 = arr[0];
    let i1 = arr[1];
    let i2 = arr[2];
    let i3 = arr[3];

    Ok(TokenStream::from(quote! {
        radix_engine_common::math::PreciseDecimal(radix_engine_common::math::I256::from_digits([#i0, #i1, #i2, #i3]))
    }))
}
