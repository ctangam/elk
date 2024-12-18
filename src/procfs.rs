use nom::{
    branch::alt,
    bytes::complete::{tag, take_while, take_while1},
    combinator::{all_consuming, map, opt, value},
    error::ParseError,
    multi::many0,
    sequence::{delimited, preceded, separated_pair, terminated, tuple},
    IResult, InputTakeAtPosition,
};
use std::fmt;

/// returns true if a character is a (lower-case) hexadecimal digit
fn is_hex_digit(c: char) -> bool {
    "0123456789abcdef".contains(c)
}

/// parses 0 or more spaces and tabs
fn whitespace<I, E>(i: I) -> IResult<I, I, E>
where
    I: InputTakeAtPosition<Item = char>,
    E: ParseError<I>,
{
    take_while(|c| " \t".contains(c))(i)
}

/// execute and return the child parser's result, ignoring leading and trailing
/// spaces and tabs
fn spaced<I, O, E>(f: impl FnMut(I) -> IResult<I, O, E>) -> impl FnMut(I) -> IResult<I, O, E>
where
    I: InputTakeAtPosition<Item = char> + Clone + PartialEq,
    E: ParseError<I>,
{
    preceded(whitespace, terminated(f, whitespace))
}

/// parses a lower-case hexadecimal number as a delf::Addr
fn hex_addr(i: &str) -> IResult<&str, delf::Addr> {
    // `take_while1` requires at least one character
    let (i, num) = take_while1(is_hex_digit)(i)?;
    // FIXME: reckless use of expect
    let u = u64::from_str_radix(num, 16).expect("our hex parser is wrong");
    Ok((i, u.into()))
}

/// parses a delf::Addr range in the form 0000-ffff
fn hex_addr_range(i: &str) -> IResult<&str, std::ops::Range<delf::Addr>> {
    let (i, (start, end)) = separated_pair(hex_addr, tag("-"), hex_addr)(i)?;
    Ok((i, start..end))
}

/// memory mapping permission bits
pub struct Perms {
    /// readable
    pub r: bool,
    /// writable
    pub w: bool,
    /// executable
    pub x: bool,
    /// not sure, tbh
    pub p: bool,
}

impl fmt::Debug for Perms {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bit = |val, display| {
            if val {
                display
            } else {
                "-"
            }
        };
        write!(
            f,
            "{}{}{}{}",
            bit(self.r, "r"),
            bit(self.w, "w"),
            bit(self.x, "x"),
            bit(self.p, "p"),
        )
    }
}

/// parses mapping permissions as seen in `/proc/:pid/maps`
fn perms(i: &str) -> IResult<&str, Perms> {
    /// parses a single permission bit. for example, the readable
    /// bit can be either "r" or "-".
    fn bit(c: &'static str) -> impl Fn(&str) -> IResult<&str, bool> {
        move |i: &str| -> IResult<&str, bool> {
            alt((value(false, tag("-")), value(true, tag(c))))(i)
        }
    }
    let (i, (r, w, x, p)) = tuple((bit("r"), bit("w"), bit("x"), bit("p")))(i)?;
    Ok((i, Perms { r, w, x, p }))
}

/// parses a decimal number as an u64
fn dec_number(i: &str) -> IResult<&str, u64> {
    let (i, s) = take_while1(|c| "0123456789".contains(c))(i)?;
    // FIXME: reckless use of expect
    let num: u64 = s.parse().expect("our decimal parser is wrong");
    Ok((i, num))
}

/// parses a hexadecimal number as an u64
fn hex_number(i: &str) -> IResult<&str, u64> {
    let (i, s) = take_while1(|c| "0123456789abcdefABCDEF".contains(c))(i)?;
    // FIXME: reckless use of expect
    let num = u64::from_str_radix(s, 16).expect("our hexadecimal parser is wrong");
    Ok((i, num))
}

/// a Linux device number
pub struct Dev {
    pub major: u64,
    pub minor: u64,
}

impl fmt::Debug for Dev {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// parses a Linux device number in form major:minor, where
/// major and minor are hexadecimal numbers
fn dev(i: &str) -> IResult<&str, Dev> {
    let (i, (major, minor)) = separated_pair(hex_number, tag(":"), hex_number)(i)?;
    Ok((i, Dev { major, minor }))
}

/// Source for a mapping: could be special (stack, vdso, etc.),
/// a file, or an anonymous mapping
#[derive(Debug)]
pub enum Source<'a> {
    /// not backed by a file
    Anonymous,
    /// not backed by a file either, *and* special-purpose
    Special(&'a str),
    /// backed by a file
    File(&'a str),
}

impl<'a> Source<'_> {
    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }
}

fn source(i: &str) -> IResult<&str, Source<'_>> {
    fn is_path_character(c: char) -> bool {
        // kinda jank, and won't support files with actual spaces in them,
        // but largely good enough for our use case.
        c != ']' && !c.is_whitespace()
    }

    fn path(i: &str) -> IResult<&str, &str> {
        take_while(is_path_character)(i)
    }

    alt((
        map(delimited(tag("["), path, tag("]")), Source::Special),
        map(path, |s| {
            if s.is_empty() {
                Source::Anonymous
            } else {
                Source::File(s)
            }
        }),
    ))(i)
}

#[derive(Debug)]
pub struct Mapping<'a> {
    pub addr_range: std::ops::Range<delf::Addr>,
    pub perms: Perms,
    pub offset: delf::Addr,
    pub dev: Dev,
    pub len: u64,
    pub source: Source<'a>,
    pub deleted: bool,
}

fn mapping(i: &str) -> IResult<&str, Mapping> {
    let (i, (addr_range, perms, offset, dev, len, source, deleted)) = tuple((
        spaced(hex_addr_range),
        spaced(perms),
        spaced(hex_addr),
        spaced(dev),
        spaced(dec_number),
        spaced(source),
        spaced(map(opt(tag("(deleted)")), |o| o.is_some())),
    ))(i)?;
    let res = Mapping {
        addr_range,
        perms,
        offset,
        dev,
        len,
        source,
        deleted,
    };
    Ok((i, res))
}

pub fn mappings(i: &str) -> IResult<&str, Vec<Mapping>> {
    all_consuming(many0(terminated(spaced(mapping), tag("\n"))))(i)
}
