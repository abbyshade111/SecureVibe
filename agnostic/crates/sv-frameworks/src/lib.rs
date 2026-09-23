//! Reading the OWASP frameworks and deciding what applies.

pub mod applicability;
pub mod load;

pub use applicability::{ApplicabilityConfig, Condition, ConditionContext, VerificationClass};
pub use load::{Frameworks, RequirementInfo};
