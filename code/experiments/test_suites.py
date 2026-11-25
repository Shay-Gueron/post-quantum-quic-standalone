from code.experiments.engine import ExperimentProfile

def create_profiles(base_measurements_count, max_fragments):
    profile_test = ExperimentProfile(
        identifier="test",
        losses=[["0%"]],
        delays=[["0ms"]],
        bandwidth=None,
        measurements_per_config=[100 // max_fragments] * max_fragments
    )

    profile_datacenter = ExperimentProfile(
        identifier="datacenter",
        losses=[["random", f"{p}%"] for p in [0, 0.025, 0.05, 0.075, 0.1]],
        delays=[["0.25ms"]],
        bandwidth=["10gbps", "10gbps"],
        measurements_per_config=[base_measurements_count // max_fragments] * max_fragments
    )

    profile_broadband = ExperimentProfile(
        identifier="broadband",
        losses=[["random", f"{p}%"] for p in [0, 0.25, 0.5, 0.75, 1]],
        delays=[["12ms"]],
        bandwidth=["300mbps", "60mbps"],
        measurements_per_config=[base_measurements_count // max_fragments] * max_fragments
    )

    profile_mobile = ExperimentProfile(
        identifier="mobile",
        losses=[["random", f"{p}%"] for p in [0, 0.25, 0.5, 0.75, 1]],
        delays=[["25ms", "5ms"]],
        bandwidth=["200mbps", "12mbps"],
        measurements_per_config=[base_measurements_count // max_fragments] * max_fragments
    )

    profile_rtt = ExperimentProfile(
        identifier="test_rtt",
        losses=[["random", f"{p}%"] for p in [0, 0.25, 0.5, 0.75, 1]],
        delays=[["10ms", "0ms"]],
        bandwidth=["100gbps", "100gbps"],
        measurements_per_config=[1000 // 5] * 5
    )

    return profile_test, profile_datacenter, profile_broadband, profile_mobile, profile_rtt

def get_test_suites(base_count, max_fragments, short_base_count=10**2):
    p_test, p_dc, p_bb, p_mob, p_rtt = create_profiles(base_count, max_fragments)
    _, s_dc, s_bb, s_mob, _ = create_profiles(short_base_count, max_fragments)

    all_tests = [p_dc, p_bb, p_mob]
    fast_tests = [p_dc]
    short_all_tests = [s_dc, s_bb, s_mob]
    short_fast_tests = [s_dc]

    main_tests = {
        ("P-256", "P-256"): all_tests,
        ("MLDSA44", "P-256"): all_tests,
        ("MLDSA44", "MLDSA44"): all_tests,
        ("MLDSA65", "MLDSA65"): fast_tests,
        ("MLDSA87", "MLDSA87"): fast_tests
    }

    rtt_tests = {
        ("P-256", "P-256"): [p_rtt],
        ("MLDSA44", "P-256"): [p_rtt],
        ("MLDSA44", "MLDSA44"): [p_rtt],
        ("MLDSA65", "MLDSA65"): [p_rtt],
        ("MLDSA87", "MLDSA87"): [p_rtt]
    }

    test_tests = {
        ("P-256", "P-256"): [p_test],
        ("MLDSA44", "P-256"): [p_test]
    }

    short_main_tests = {
        ("P-256", "P-256"): short_all_tests,
        ("MLDSA44", "P-256"): short_all_tests,
        ("MLDSA44", "MLDSA44"): short_all_tests,
        ("MLDSA65", "MLDSA65"): short_fast_tests,
        ("MLDSA87", "MLDSA87"): short_fast_tests
    }

    return {
        "main_tests": main_tests,
        "short_main_tests": short_main_tests,
        "rtt_tests": rtt_tests,
        "test_tests": test_tests
    }
