from bearwatch.versions import Version, in_range


def test_ordering():
    assert Version("120.0.6099.71") < Version("120.0.6099.109")
    assert Version("23.01") > Version("22.01")
    assert Version("1.2") == Version("1.2.0")
    assert Version("1.0") > Version("1.0beta")
    assert Version("10.0.22631.4317") > Version("10.0.22631.4037")


def test_ranges():
    assert in_range("120.0.6099.71", end_excl="120.0.6099.109")
    assert not in_range("120.0.6099.109", end_excl="120.0.6099.109")
    assert in_range("5.0", start_incl="5.0", end_incl="5.4")
    assert not in_range("5.0", start_excl="5.0", end_incl="5.4")
    assert in_range("23.01", exact="23.01")
    assert not in_range("23.01", exact="22.01")
    # '*' with no bounds means every version
    assert in_range("9.9", exact="*")
    assert not in_range("", exact="*")
