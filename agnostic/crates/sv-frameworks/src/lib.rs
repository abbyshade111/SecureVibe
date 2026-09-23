//! Reading the OWASP frameworks and deciding what applies.

pub mod applicability;
pub mod condition;
pub mod load;

pub use applicability::{ApplicabilityConfig, ConditionContext, VerificationClass};
pub use condition::{Condition, Source};
pub use load::{Frameworks, RequirementInfo};
