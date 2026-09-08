petal::route_file!(
    spec: petal::static_dir_spec(),
    list: crate::static_list(&[
        ("order.json", false, true),
        ("cancel.json", false, true),
        ("cancel_by_cloid.json", false, true),
        ("schedule_cancel.json", false, true),
        ("update_leverage.json", false, true),
        ("raw_signed.json", false, true),
        ("usd_send.json", false, true),
        ("usd_class_transfer.json", false, true),
        ("approve_builder_fee.json", false, true),
        ("send_asset.json", false, true),
        ("last_response.json", false, false),
    ])
);
