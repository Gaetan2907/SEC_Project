use casbin::prelude::*;

pub const CONFIG: &str = "accessControl/king_model.conf";
pub const POLICY: &str = "accessControl/king_policy.csv";

///Centralized access control mechanism
pub async fn is_allowed(subject: &str, resource: &str) -> bool {
    let e = Enforcer::new(CONFIG, POLICY)
        .await
        .expect("cannot read model or policy");
    match e.enforce((subject, resource)) {
        Ok(authorized) => return authorized,
        Err(_) => {
            panic!("Casbin model does not map request");
        }
    }
}
