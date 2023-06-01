// name = "getopts"
// version = "0.2.21"
// authors = ["The Rust Project Developers"]
// description = "getopts-like option parsing.\n"
// homepage = "https://github.com/rust-lang/getopts"
// documentation = "https://doc.rust-lang.org/getopts"
// modified = kiven lee
// modified_date = 2023-05-15

use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::iter::{repeat, IntoIterator};
use std::result;
use std::str::FromStr;

trait ChineseStr {
    fn width(&self) -> usize;
}

impl ChineseStr for str {
    // 计算带中文的字符串显示宽度，1个英文字符宽1，1个中文字符宽2，忽略ansi颜色控制代码
    fn width(&self) -> usize {
        let bs = self.as_bytes();
        let (mut total, mut i, imax) = (0, 0, bs.len());
        while i < imax {
            let ch = bs[i];
            i += if ch <= 127 {
                if ch == 0x1b && i + 3 < imax {
                    if bs[i + 2] == b'0' { 4 } else { 5 }
                } else {
                    total += 1;
                    1
                }
            } else {
                total += 2;
                3
            }
        }
        total
    }
}


/// A description of the options that a program can handle.
pub struct Options {
    grps: Vec<OptGroup>,
    parsing_style: ParsingStyle,
    long_only: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self::new()
    }
}

impl Options {
    /// Create a blank set of options.
    pub fn new() -> Options {
        Options {
            grps: Vec::new(),
            parsing_style: ParsingStyle::FloatingFrees,
            long_only: false,
        }
    }

    /// Set the parsing style.
    pub fn parsing_style(&mut self, style: ParsingStyle) -> &mut Options {
        self.parsing_style = style;
        self
    }

    /// Set or clear "long options only" mode.
    ///
    /// In "long options only" mode, short options cannot be clustered
    /// together, and long options can be given with either a single
    /// "-" or the customary "--".  This mode also changes the meaning
    /// of "-a=b"; in the ordinary mode this will parse a short option
    /// "-a" with argument "=b"; whereas in long-options-only mode the
    /// argument will be simply "b".
    pub fn long_only(&mut self, long_only: bool) -> &mut Options {
        self.long_only = long_only;
        self
    }

    /// Create a generic option group, stating all parameters explicitly.
    pub fn opt(&mut self, short_name: &str, long_name: &str, desc: &str, hint: &str,
            hasarg: HasArg, occur: Occur,) -> &mut Options {
        validate_names(short_name, long_name);
        self.grps.push(OptGroup {
            short_name: String::from(short_name),
            long_name: String::from(long_name),
            hint: String::from(hint),
            desc: String::from(desc),
            hasarg,
            occur,
        });
        self
    }

    /// Create a long option that is optional and does not take an argument.
    ///
    /// * `short_name` - e.g. `"h"` for a `-h` option, or `""` for none
    /// * `long_name` - e.g. `"help"` for a `--help` option, or `""` for none
    /// * `desc` - Description for usage help
    pub fn optflag(&mut self, short_name: &str, long_name: &str, desc: &str) -> &mut Options {
        self.opt(short_name, long_name, desc, "", HasArg::No, Occur::Optional)
    }

    /// Create a long option that can occur more than once and does not
    /// take an argument.
    ///
    /// * `short_name` - e.g. `"h"` for a `-h` option, or `""` for none
    /// * `long_name` - e.g. `"help"` for a `--help` option, or `""` for none
    /// * `desc` - Description for usage help
    pub fn optflagmulti(&mut self, short_name: &str, long_name: &str, desc: &str) -> &mut Options {
        self.opt(short_name, long_name, desc, "", HasArg::No, Occur::Multi)
    }

    /// Create a long option that is optional and takes an optional argument.
    ///
    /// * `short_name` - e.g. `"h"` for a `-h` option, or `""` for none
    /// * `long_name` - e.g. `"help"` for a `--help` option, or `""` for none
    /// * `desc` - Description for usage help
    /// * `hint` - Hint that is used in place of the argument in the usage help,
    ///   e.g. `"FILE"` for a `-o FILE` option
    pub fn optflagopt(&mut self, short_name: &str, long_name: &str, desc: &str, hint: &str,) -> &mut Options {
        self.opt(short_name, long_name, desc, hint, HasArg::Maybe, Occur::Optional)
    }

    /// Create a long option that is optional, takes an argument, and may occur
    /// multiple times.
    ///
    /// * `short_name` - e.g. `"h"` for a `-h` option, or `""` for none
    /// * `long_name` - e.g. `"help"` for a `--help` option, or `""` for none
    /// * `desc` - Description for usage help
    /// * `hint` - Hint that is used in place of the argument in the usage help,
    ///   e.g. `"FILE"` for a `-o FILE` option
    pub fn optmulti(&mut self, short_name: &str, long_name: &str, desc: &str, hint: &str,) -> &mut Options {
        self.opt(short_name, long_name, desc, hint, HasArg::Yes, Occur::Multi)
    }

    /// Create a long option that is optional and takes an argument.
    ///
    /// * `short_name` - e.g. `"h"` for a `-h` option, or `""` for none
    /// * `long_name` - e.g. `"help"` for a `--help` option, or `""` for none
    /// * `desc` - Description for usage help
    /// * `hint` - Hint that is used in place of the argument in the usage help,
    ///   e.g. `"FILE"` for a `-o FILE` option
    pub fn optopt(&mut self, short_name: &str, long_name: &str, desc: &str, hint: &str,) -> &mut Options {
        self.opt(short_name, long_name, desc, hint, HasArg::Yes, Occur::Optional)
    }

    /// Create a long option that is required and takes an argument.
    ///
    /// * `short_name` - e.g. `"h"` for a `-h` option, or `""` for none
    /// * `long_name` - e.g. `"help"` for a `--help` option, or `""` for none
    /// * `desc` - Description for usage help
    /// * `hint` - Hint that is used in place of the argument in the usage help,
    ///   e.g. `"FILE"` for a `-o FILE` option
    pub fn reqopt(&mut self, short_name: &str, long_name: &str, desc: &str, hint: &str,) -> &mut Options {
        self.opt(short_name, long_name, desc, hint, HasArg::Yes, Occur::Req)
    }

    /// Parse command line arguments according to the provided options.
    ///
    /// On success returns `Ok(Matches)`. Use methods such as `opt_present`
    /// `opt_str`, etc. to interrogate results.
    /// # Panics
    ///
    /// Returns `Err(Fail)` on failure: use the `Debug` implementation of `Fail`
    /// to display information about it.
    pub fn parse<C>(&self, args: C) -> Result
    where
        C: IntoIterator,
        C::Item: AsRef<OsStr>,
    {
        let opts: Vec<Opt> = self.grps.iter().map(|x| x.long_to_short()).collect();

        let mut vals = (0..opts.len())
            .map(|_| Vec::new())
            .collect::<Vec<Vec<(usize, Optval)>>>();
        let mut free: Vec<String> = Vec::new();
        let args = args
            .into_iter()
            .map(|i| {
                i.as_ref()
                    .to_str()
                    .ok_or_else(|| Fail::UnrecognizedOption(format!("{:?}", i.as_ref())))
                    .map(|s| String::from(s))
            })
            .collect::<::std::result::Result<Vec<_>, _>>()?;
        let mut args = args.into_iter().peekable();
        let mut arg_pos = 0;
        while let Some(cur) = args.next() {
            if !is_arg(&cur) {
                free.push(cur);
                match self.parsing_style {
                    ParsingStyle::FloatingFrees => {}
                    ParsingStyle::StopAtFirstFree => {
                        free.extend(args);
                        break;
                    }
                }
            } else if cur == "--" {
                free.extend(args);
                break;
            } else {
                let mut names;
                let mut i_arg = None;
                let mut was_long = true;
                if cur.as_bytes()[1] == b'-' || self.long_only {
                    let tail = if cur.as_bytes()[1] == b'-' {
                        &cur[2..]
                    } else {
                        assert!(self.long_only);
                        &cur[1..]
                    };
                    let mut parts = tail.splitn(2, '=');
                    names = vec![Name::from_str(parts.next().unwrap())];
                    if let Some(rest) = parts.next() {
                        i_arg = Some(String::from(rest));
                    }
                } else {
                    was_long = false;
                    names = Vec::new();
                    for (j, ch) in cur.char_indices().skip(1) {
                        let opt = Name::Short(ch);

                        /* In a series of potential options (eg. -aheJ), if we
                           see one which takes an argument, we assume all
                           subsequent characters make up the argument. This
                           allows options such as -L/usr/local/lib/foo to be
                           interpreted correctly
                        */

                        let opt_id = match find_opt(&opts, &opt) {
                            Some(id) => id,
                            None => return Err(Fail::UnrecognizedOption(opt.to_string())),
                        };

                        names.push(opt);

                        let arg_follows = match opts[opt_id].hasarg {
                            HasArg::Yes | HasArg::Maybe => true,
                            HasArg::No => false,
                        };

                        if arg_follows {
                            let next = j + ch.len_utf8();
                            if next < cur.len() {
                                i_arg = Some(String::from(&cur[next..]));
                                break;
                            }
                        }
                    }
                }
                let mut name_pos = 0;
                for nm in names.iter() {
                    name_pos += 1;
                    let optid = match find_opt(&opts, &nm) {
                        Some(id) => id,
                        None => return Err(Fail::UnrecognizedOption(nm.to_string())),
                    };
                    match opts[optid].hasarg {
                        HasArg::No => {
                            if name_pos == names.len() && i_arg.is_some() {
                                return Err(Fail::UnexpectedArgument(nm.to_string()));
                            }
                            vals[optid].push((arg_pos, Optval::Given));
                        }
                        HasArg::Maybe => {
                            // Note that here we do not handle `--arg value`.
                            // This matches GNU getopt behavior; but also
                            // makes sense, because if this were accepted,
                            // then users could only write a "Maybe" long
                            // option at the end of the arguments when
                            // FloatingFrees is in use.
                            if let Some(i_arg) = i_arg.take() {
                                vals[optid].push((arg_pos, Optval::Val(i_arg)));
                            } else if was_long
                                || name_pos < names.len()
                                || args.peek().map_or(true, |n| is_arg(&n))
                            {
                                vals[optid].push((arg_pos, Optval::Given));
                            } else {
                                vals[optid].push((arg_pos, Optval::Val(args.next().unwrap())));
                            }
                        }
                        HasArg::Yes => {
                            if let Some(i_arg) = i_arg.take() {
                                vals[optid].push((arg_pos, Optval::Val(i_arg)));
                            } else if let Some(n) = args.next() {
                                vals[optid].push((arg_pos, Optval::Val(n)));
                            } else {
                                return Err(Fail::ArgumentMissing(nm.to_string()));
                            }
                        }
                    }
                }
            }
            arg_pos += 1;
        }
        debug_assert_eq!(vals.len(), opts.len());
        for (vals, opt) in vals.iter().zip(opts.iter()) {
            if opt.occur == Occur::Req && vals.is_empty() {
                return Err(Fail::OptionMissing(opt.name.to_string()));
            }
            if opt.occur != Occur::Multi && vals.len() > 1 {
                return Err(Fail::OptionDuplicated(opt.name.to_string()));
            }
        }
        Ok(Matches { opts, vals, free })
    }

    /// Derive a short one-line usage summary from a set of long options.
    pub fn short_usage(&self, program_name: &str) -> String {
        #[cfg(not(feature = "chinese"))]
        let mut line = format!("Usage: {} ", program_name);
        #[cfg(feature = "chinese")]
        let mut line = format!("使用方法: {} ", program_name);

        line.push_str(
            &self
                .grps
                .iter()
                .map(format_option)
                .collect::<Vec<String>>()
                .join(" "),
        );
        line
    }

    /// Derive a formatted message from a set of options.
    pub fn usage(&self, brief: &str) -> String {
        #[cfg(not(feature = "chinese"))]
        let oname = "Options";
        #[cfg(feature = "chinese")]
        let oname = "选项";

        self.usage_with_format(|opts| {
            format!(
                "{}\n\n{}:\n{}\n",
                brief,
                oname,
                opts.collect::<Vec<String>>().join("\n")
            )
        })

    }

    /// Derive a custom formatted message from a set of options. The formatted options provided to
    /// a closure as an iterator.
    pub fn usage_with_format<F> (&self, mut formatter: F) -> String
    where
        F: FnMut(&mut dyn Iterator<Item = String>) -> String,
    {
        formatter(&mut self.usage_items())
    }

    /// Derive usage items from a set of options.
    fn usage_items<'a>(&'a self) -> Box<dyn Iterator<Item = String> + 'a> {
        let desc_sep = format!("\n{}", repeat(" ").take(24).collect::<String>());

        let any_short = self.grps.iter().any(|optref| !optref.short_name.is_empty());

        let rows = self.grps.iter().map(move |optref| {
            let OptGroup {
                short_name,
                long_name,
                hint,
                desc,
                hasarg,
                ..
            } = (*optref).clone();

            let mut row = String::from("    ");

            // short option
            match short_name.width() {
                0 => {
                    if any_short {
                        row.push_str("    ");
                    }
                }
                1 => {
                    row.push('-');
                    row.push_str(&short_name);
                    if long_name.width() > 0 {
                        row.push_str(", ");
                    } else {
                        // Only a single space here, so that any
                        // argument is printed in the correct spot.
                        row.push(' ');
                    }
                }
                // FIXME: refer issue #7.
                _ => panic!("the short name should only be 1 ascii char long"),
            }

            // long option
            match long_name.width() {
                0 => {}
                _ => {
                    row.push_str(if self.long_only { "-" } else { "--" });
                    row.push_str(&long_name);
                    row.push(' ');
                }
            }

            // arg
            match hasarg {
                HasArg::No => {}
                HasArg::Yes => row.push_str(&hint),
                HasArg::Maybe => {
                    row.push('[');
                    row.push_str(&hint);
                    row.push(']');
                }
            }

            let rowlen = row.width();
            if rowlen < 24 {
                for _ in 0..24 - rowlen {
                    row.push(' ');
                }
            } else {
                row.push_str(&desc_sep)
            }

            let desc_rows = each_split_within(&desc, 54);
            row.push_str(&desc_rows.join(&desc_sep));

            row
        });

        Box::new(rows)
    }
}

fn validate_names(short_name: &str, long_name: &str) {
    let len = short_name.len();
    assert!(
        len == 1 || len == 0,
        "the short_name (first argument) should be a single character, \
         or an empty string for none"
    );
    let len = long_name.len();
    assert!(
        len == 0 || len > 1,
        "the long_name (second argument) should be longer than a single \
         character, or an empty string for none"
    );
}

/// What parsing style to use when parsing arguments.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ParsingStyle {
    /// Flags and "free" arguments can be freely inter-mixed.
    FloatingFrees,
    /// As soon as a "free" argument (i.e. non-flag) is encountered, stop
    /// considering any remaining arguments as flags.
    StopAtFirstFree,
}

/// Name of an option. Either a string or a single char.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Name {
    /// A string representing the long name of an option.
    /// For example: "help"
    Long(String),
    /// A char representing the short name of an option.
    /// For example: 'h'
    Short(char),
}

/// Describes whether an option has an argument.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum HasArg {
    /// The option requires an argument.
    Yes,
    /// The option takes no argument.
    No,
    /// The option argument is optional.
    Maybe,
}

/// Describes how often an option may occur.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum Occur {
    /// The option occurs once.
    Req,
    /// The option occurs at most once.
    Optional,
    /// The option occurs zero or more times.
    Multi,
}

/// A description of a possible option.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Opt {
    /// Name of the option
    name: Name,
    /// Whether it has an argument
    hasarg: HasArg,
    /// How often it can occur
    occur: Occur,
    /// Which options it aliases
    aliases: Vec<Opt>,
}

/// One group of options, e.g., both `-h` and `--help`, along with
/// their shared description and properties.
#[derive(Clone, PartialEq, Eq)]
struct OptGroup {
    /// Short name of the option, e.g. `h` for a `-h` option
    short_name: String,
    /// Long name of the option, e.g. `help` for a `--help` option
    long_name: String,
    /// Hint for argument, e.g. `FILE` for a `-o FILE` option
    hint: String,
    /// Description for usage help text
    desc: String,
    /// Whether option has an argument
    hasarg: HasArg,
    /// How often it can occur
    occur: Occur,
}

/// Describes whether an option is given at all or has a value.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Optval {
    Val(String),
    Given,
}

/// The result of checking command line arguments. Contains a vector
/// of matches and a vector of free strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Matches {
    /// Options that matched
    opts: Vec<Opt>,
    /// Values of the Options that matched and their positions
    vals: Vec<Vec<(usize, Optval)>>,
    /// Free string fragments
    pub free: Vec<String>,
}

/// The type returned when the command line does not conform to the
/// expected format. Use the `Debug` implementation to output detailed
/// information.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail {
    /// The option requires an argument but none was passed.
    ArgumentMissing(String),
    /// The passed option is not declared among the possible options.
    UnrecognizedOption(String),
    /// A required option is not present.
    OptionMissing(String),
    /// A single occurrence option is being used multiple times.
    OptionDuplicated(String),
    /// There's an argument being passed to a non-argument option.
    UnexpectedArgument(String),
}

impl Error for Fail {
    fn description(&self) -> &str {
        match *self {
            Fail::ArgumentMissing(_) => "missing argument",
            Fail::UnrecognizedOption(_) => "unrecognized option",
            Fail::OptionMissing(_) => "missing option",
            Fail::OptionDuplicated(_) => "duplicated option",
            Fail::UnexpectedArgument(_) => "unexpected argument",
        }
    }
}

/// The result of parsing a command line with a set of options.
pub type Result = result::Result<Matches, Fail>;

impl Name {
    fn from_str(nm: &str) -> Name {
        if nm.len() == 1 {
            Name::Short(nm.as_bytes()[0] as char)
        } else {
            Name::Long(String::from(nm))
        }
    }

    fn to_string(&self) -> String {
        match *self {
            Name::Short(ch) => ch.to_string(),
            Name::Long(ref s) => s.to_string(),
        }
    }
}

impl OptGroup {
    /// Translate OptGroup into Opt.
    /// (Both short and long names correspond to different Opts).
    fn long_to_short(&self) -> Opt {
        let OptGroup {
            short_name,
            long_name,
            hasarg,
            occur,
            ..
        } = (*self).clone();

        match (short_name.len(), long_name.len()) {
            (0, 0) => panic!("this long-format option was given no name"),
            (0, _) => Opt {
                name: Name::Long(long_name),
                hasarg,
                occur,
                aliases: Vec::new(),
            },
            (1, 0) => Opt {
                name: Name::Short(short_name.as_bytes()[0] as char),
                hasarg,
                occur,
                aliases: Vec::new(),
            },
            (1, _) => Opt {
                name: Name::Long(long_name),
                hasarg,
                occur,
                aliases: vec![Opt {
                    name: Name::Short(short_name.as_bytes()[0] as char),
                    hasarg: hasarg,
                    occur: occur,
                    aliases: Vec::new(),
                }],
            },
            (_, _) => panic!("something is wrong with the long-form opt"),
        }
    }
}

impl Matches {
    fn opt_vals(&self, nm: &str) -> Vec<(usize, Optval)> {
        match find_opt(&self.opts, &Name::from_str(nm)) {
            Some(id) => self.vals[id].clone(),
            None => panic!("No option '{}' defined", nm),
        }
    }

    fn opt_val(&self, nm: &str) -> Option<Optval> {
        self.opt_vals(nm).into_iter().map(|(_, o)| o).next()
    }
    /// Returns true if an option was defined
    pub fn opt_defined(&self, nm: &str) -> bool {
        find_opt(&self.opts, &Name::from_str(nm)).is_some()
    }

    /// Returns true if an option was matched.
    pub fn opt_present(&self, nm: &str) -> bool {
        !self.opt_vals(nm).is_empty()
    }

    /// Returns the number of times an option was matched.
    pub fn opt_count(&self, nm: &str) -> usize {
        self.opt_vals(nm).len()
    }

    /// Returns a vector of all the positions in which an option was matched.
    pub fn opt_positions(&self, nm: &str) -> Vec<usize> {
        self.opt_vals(nm).into_iter().map(|(pos, _)| pos).collect()
    }

    /// Returns true if any of several options were matched.
    pub fn opts_present(&self, names: &[String]) -> bool {
        names
            .iter()
            .any(|nm| match find_opt(&self.opts, &Name::from_str(&nm)) {
                Some(id) if !self.vals[id].is_empty() => true,
                _ => false,
            })
    }

    /// Returns the string argument supplied to one of several matching options or `None`.
    pub fn opts_str(&self, names: &[String]) -> Option<String> {
        names
            .iter()
            .filter_map(|nm| match self.opt_val(&nm) {
                Some(Optval::Val(s)) => Some(s),
                _ => None,
            })
            .next()
    }

    /// Returns a vector of the arguments provided to all matches of the given
    /// option.
    ///
    /// Used when an option accepts multiple values.
    pub fn opt_strs(&self, nm: &str) -> Vec<String> {
        self.opt_vals(nm)
            .into_iter()
            .filter_map(|(_, v)| match v {
                Optval::Val(s) => Some(s),
                _ => None,
            })
            .collect()
    }

    /// Returns a vector of the arguments provided to all matches of the given
    /// option, together with their positions.
    ///
    /// Used when an option accepts multiple values.
    pub fn opt_strs_pos(&self, nm: &str) -> Vec<(usize, String)> {
        self.opt_vals(nm)
            .into_iter()
            .filter_map(|(p, v)| match v {
                Optval::Val(s) => Some((p, s)),
                _ => None,
            })
            .collect()
    }

    /// Returns the string argument supplied to a matching option or `None`.
    pub fn opt_str(&self, nm: &str) -> Option<String> {
        match self.opt_val(nm) {
            Some(Optval::Val(s)) => Some(s),
            _ => None,
        }
    }

    /// Returns the matching string, a default, or `None`.
    ///
    /// Returns `None` if the option was not present, `def` if the option was
    /// present but no argument was provided, and the argument if the option was
    /// present and an argument was provided.
    pub fn opt_default(&self, nm: &str, def: &str) -> Option<String> {
        match self.opt_val(nm) {
            Some(Optval::Val(s)) => Some(s),
            Some(_) => Some(String::from(def)),
            None => None,
        }
    }

    /// Returns some matching value or `None`.
    ///
    /// Similar to opt_str, also converts matching argument using FromStr.
    pub fn opt_get<T>(&self, nm: &str) -> result::Result<Option<T>, T::Err>
    where
        T: FromStr,
    {
        match self.opt_val(nm) {
            Some(Optval::Val(s)) => Ok(Some(s.parse()?)),
            Some(Optval::Given) => Ok(None),
            None => Ok(None),
        }
    }

    /// Returns a matching value or default.
    ///
    /// Similar to opt_default, except the two differences.
    /// Instead of returning None when argument was not present, return `def`.
    /// Instead of returning &str return type T, parsed using str::parse().
    pub fn opt_get_default<T>(&self, nm: &str, def: T) -> result::Result<T, T::Err>
    where
        T: FromStr,
    {
        match self.opt_val(nm) {
            Some(Optval::Val(s)) => s.parse(),
            Some(Optval::Given) => Ok(def),
            None => Ok(def),
        }
    }
}

fn is_arg(arg: &str) -> bool {
    arg.as_bytes().get(0) == Some(&b'-') && arg.len() > 1
}

fn find_opt(opts: &[Opt], nm: &Name) -> Option<usize> {
    // Search main options.
    let pos = opts.iter().position(|opt| &opt.name == nm);
    if pos.is_some() {
        return pos;
    }

    // Search in aliases.
    for candidate in opts.iter() {
        if candidate.aliases.iter().any(|opt| &opt.name == nm) {
            return opts.iter().position(|opt| opt.name == candidate.name);
        }
    }

    None
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Fail::ArgumentMissing(ref nm) => write!(f, "Argument to option '{}' missing", *nm),
            Fail::UnrecognizedOption(ref nm) => write!(f, "Unrecognized option: '{}'", *nm),
            Fail::OptionMissing(ref nm) => write!(f, "Required option '{}' missing", *nm),
            Fail::OptionDuplicated(ref nm) => write!(f, "Option '{}' given more than once", *nm),
            Fail::UnexpectedArgument(ref nm) => write!(f, "Option '{}' does not take an argument", *nm),
        }
    }
}

fn format_option(opt: &OptGroup) -> String {
    let mut line = String::new();

    if opt.occur != Occur::Req {
        line.push('[');
    }

    // Use short_name if possible, but fall back to long_name.
    if !opt.short_name.is_empty() {
        line.push('-');
        line.push_str(&opt.short_name);
    } else {
        line.push_str("--");
        line.push_str(&opt.long_name);
    }

    if opt.hasarg != HasArg::No {
        line.push(' ');
        if opt.hasarg == HasArg::Maybe {
            line.push('[');
        }
        line.push_str(&opt.hint);
        if opt.hasarg == HasArg::Maybe {
            line.push(']');
        }
    }

    if opt.occur != Occur::Req {
        line.push(']');
    }
    if opt.occur == Occur::Multi {
        line.push_str("..");
    }

    line
}

/// Splits a string into substrings with possibly internal whitespace,
/// each of them at most `lim` bytes long, if possible. The substrings
/// have leading and trailing whitespace removed, and are only cut at
/// whitespace boundaries.
fn each_split_within(desc: &str, lim: usize) -> Vec<String> {
    let mut rows = Vec::new();
    for line in desc.trim().lines() {
        let line_chars = line.chars().chain(Some(' '));
        let words = line_chars
            .fold((Vec::new(), 0, 0), |(mut words, a, z), c| {
                let idx = z + c.len_utf8(); // Get the current byte offset

                // If the char is whitespace, advance the word start and maybe push a word
                if c.is_whitespace() {
                    if a != z {
                        words.push(&line[a..z]);
                    }
                    (words, idx, idx)
                }
                // If the char is not whitespace, continue, retaining the current
                else {
                    (words, a, idx)
                }
            })
            .0;

        let mut row = String::new();
        for word in words.iter() {
            let sep = if !row.is_empty() { Some(" ") } else { None };
            let width = row.width() + word.width() + sep.map(ChineseStr::width).unwrap_or(0);

            if width <= lim {
                if let Some(sep) = sep {
                    row.push_str(sep)
                }
                row.push_str(word);
                continue;
            }
            if !row.is_empty() {
                rows.push(row.clone());
                row.clear();
            }
            row.push_str(word);
        }
        if !row.is_empty() {
            rows.push(row);
        }
    }
    rows
}
