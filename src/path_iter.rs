pub struct PathIter<'a> {
    path: &'a str,
    finished: bool,
}

impl<'a> PathIter<'a> {
    pub fn new(path: &'a str) -> Self {
        Self { path, finished: false }
    }
}

impl<'a> Iterator for PathIter<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.path.is_empty() {
            return None;
        }

        let result = self.path;

        self.path = match self.path.rfind('/') {
            Some(pos) if pos > 0 => &self.path[..pos],
            _ => {
                if !self.finished {
                    self.finished = true;
                    "/"
                } else {
                    ""
                }
            },
        };

        Some(result)
    }
}
