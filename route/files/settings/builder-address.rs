petal::route_file!(
    spec: petal::write_spec().caps(&["bloom:store"]),
    read: |_ctx: &petal::Ctx| {
        petal::DispatchResponse::Read(
            b"write a lowercase 0x builder address to override the default builder used by approve_builder_fee.json when its caller omits one; write an empty body to clear the override and revert to the embedded release default, if any\n".to_vec(),
        )
    },
    write: |_ctx: &petal::Ctx, body: &[u8]| {
        if let Err(response) = crate::validate_body_size(body) {
            return response;
        }
        crate::set_builder_address_override(body)
    }
);
