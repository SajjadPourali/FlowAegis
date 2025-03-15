use aya_ebpf::{
    helpers::bpf_get_current_uid_gid, macros::cgroup_sock_addr, programs::SockAddrContext,
};
use aya_log_ebpf::info;
use ebpf_common::Host;

use crate::RULES;

#[cgroup_sock_addr(connect4)]
pub fn connect4(ctx: SockAddrContext) -> i32 {
    let uid = bpf_get_current_uid_gid() as u32;

    // let i = RULES.get_ptr(1).unwrap();

    
    let Some(i) = RULES.get(1) else{
        return 1;
    };

        // let mut buf = [0u8; 100];
        // let p = core::ptr::copy(i,&mut buf,100);
        for ii in i.iter(){
            info!(&ctx, "connect4 {}", *ii);
        }

    // if i == 1{
    //     info!(&ctx, "connect44 {}", uid);
    // }
    // let out: ebpf_common::Rule = from_bytes(i).unwrap();
    info!(&ctx, "connect4 {}", uid);

    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    let transport_protocol = bpf_sock_addr.protocol as u16;

    1
}

#[cgroup_sock_addr(connect6)]
pub fn connect6(ctx: SockAddrContext) -> i32 {
    let uid = bpf_get_current_uid_gid() as u32;
    info!(&ctx, "connect6 {}", uid);
    let bpf_sock_addr = unsafe { *ctx.sock_addr };
    let transport_protocol = bpf_sock_addr.protocol as u16;

    1
}
