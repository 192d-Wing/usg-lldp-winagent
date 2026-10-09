//! Service configuration calls the `windows-service` crate does not
//! expose.

use windows::Win32::System::Services::{
    ChangeServiceConfig2W, CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT,
    SERVICE_CHANGE_CONFIG, SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
    SERVICE_REQUIRED_PRIVILEGES_INFOW,
};
use windows::core::{PCWSTR, PWSTR};

use crate::util::to_wide;

/// Sets the service's `RequiredPrivileges` list. The SCM removes every
/// other privilege from the process token at start.
#[allow(unsafe_code)]
pub fn set_required_privileges(service_name: &str, privileges: &[&str]) -> Result<(), String> {
    let mut multi: Vec<u16> = Vec::new();
    for p in privileges {
        multi.extend(p.encode_utf16());
        multi.push(0);
    }
    multi.push(0);
    let name = to_wide(service_name);
    // SAFETY: all handles are closed before returning; the multi-string
    // buffer outlives the call.
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            .map_err(|e| format!("OpenSCManagerW: {e}"))?;
        let svc = match OpenServiceW(scm, PCWSTR(name.as_ptr()), SERVICE_CHANGE_CONFIG) {
            Ok(h) => h,
            Err(e) => {
                let _ = CloseServiceHandle(scm);
                return Err(format!("OpenServiceW: {e}"));
            }
        };
        let mut info = SERVICE_REQUIRED_PRIVILEGES_INFOW {
            pmszRequiredPrivileges: PWSTR(multi.as_mut_ptr()),
        };
        let r = ChangeServiceConfig2W(
            svc,
            SERVICE_CONFIG_REQUIRED_PRIVILEGES_INFO,
            Some((&raw mut info).cast()),
        );
        let _ = CloseServiceHandle(svc);
        let _ = CloseServiceHandle(scm);
        r.map_err(|e| format!("ChangeServiceConfig2W: {e}"))
    }
}
