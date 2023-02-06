//! Generic access rights

pub trait AccessRights {
    /// The capability gives no access right
    fn is_null(&self) -> bool;

    /// Access right relationship
    fn is_subset(&self, other: &Self) -> bool;

    /// Validate a duplicate operation.
    fn is_valid_dup(&self, op1: &Self, op2: &Self) -> bool;

    /// Get a null access right.
    fn get_null() -> Self;
}
