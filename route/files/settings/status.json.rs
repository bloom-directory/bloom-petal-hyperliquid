petal::route_file!(spec: petal::store_read_spec().caps(&["bloom:store"]), read: |_ctx: &petal::Ctx| {
    match crate::builder_address_status() {
        Ok(status) => petal::read_json_value(&status),
        Err(response) => response,
    }
});
