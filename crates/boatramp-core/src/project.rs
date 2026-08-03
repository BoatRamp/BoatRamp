//! Project scoping for the store: the wire [`Project`] types (re-exported from
//! [`boatramp_types::project`]) plus [`ProjectRef`], a borrowing newtype threaded as
//! the **first argument** of every per-name `DeployStore` method. Using a distinct type
//! (not a bare `&str`) makes the store-wide scoping change compiler-enforced — you
//! cannot pass a site name where a project is meant — and lets the compiler enumerate
//! every call site during the re-key.

pub use boatramp_types::project::*;

/// A borrowed project name scoping a store operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProjectRef<'a>(&'a str);

impl<'a> ProjectRef<'a> {
    /// The `default` project — every pre-project resource + the CLI default. The only
    /// place the literal is written is [`DEFAULT_PROJECT`].
    pub const DEFAULT: ProjectRef<'static> = ProjectRef(DEFAULT_PROJECT);

    /// Scope to the named project.
    pub fn new(name: &'a str) -> Self {
        ProjectRef(name)
    }

    /// The underlying project name.
    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl<'a> From<&'a str> for ProjectRef<'a> {
    fn from(name: &'a str) -> Self {
        ProjectRef(name)
    }
}

impl std::fmt::Display for ProjectRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_ref_default_and_wrap() {
        assert_eq!(ProjectRef::DEFAULT.as_str(), "default");
        assert_eq!(ProjectRef::new("acme").as_str(), "acme");
        assert_eq!(ProjectRef::from("shop").to_string(), "shop");
    }
}
