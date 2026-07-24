petal::route_file!(
    spec: petal::static_dir_spec(),
    list: crate::static_list(&[
        ("1m.json", false, false),
        ("3m.json", false, false),
        ("5m.json", false, false),
        ("15m.json", false, false),
        ("30m.json", false, false),
        ("1h.json", false, false),
        ("2h.json", false, false),
        ("4h.json", false, false),
        ("8h.json", false, false),
        ("12h.json", false, false),
        ("1d.json", false, false),
        ("3d.json", false, false),
        ("1w.json", false, false),
        ("1M.json", false, false),
    ])
);
