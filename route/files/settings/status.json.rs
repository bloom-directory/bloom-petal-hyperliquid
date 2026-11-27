petal::route_file!(spec: petal::static_read_spec(), read: |_ctx: &petal::Ctx| {
    petal::read_json_value(&crate::builder_address_status())
});
