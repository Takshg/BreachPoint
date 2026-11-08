import pytest

from src.ask_the_data.ask import UnsafeSQL, entities, extract_sql, validate_sql


@pytest.mark.parametrize("sql", [
    "DROP TABLE top500", "DELETE FROM top500", "UPDATE top500 SET rank = 1", "INSERT INTO assets VALUES ('a')",
    "SELECT * FROM qa_cache", "SELECT * FROM pg_shadow", "SELECT * FROM pg_catalog.pg_roles", "SELECT pg_sleep(60)",
    "SELECT pg_read_file('/etc/passwd')", "SELECT 1; DROP TABLE top500", "CREATE TABLE x (a int)", "SELECT * INTO x FROM top500",
    "COPY top500 TO '/tmp/x'", "WITH d AS (DELETE FROM top500 RETURNING *) SELECT * FROM d", "not sql at all ((",
    "SELECT * FROM top500 LIMIT (SELECT 5)"])
def test_unsafe_sql_is_refused(sql):
    with pytest.raises(UnsafeSQL):
        validate_sql(sql)


def test_safe_sql_gets_a_row_cap():
    assert "LIMIT 1000" in validate_sql("SELECT cve_id FROM top500")
    assert "LIMIT 5" in validate_sql("SELECT cve_id FROM top500 LIMIT 5")
    assert "LIMIT 1000" in validate_sql("SELECT cve_id FROM top500 LIMIT 999999")


def test_join_and_cte_allowed():
    validate_sql("SELECT f.cve_id FROM asset_findings f JOIN assets a ON a.asset = f.asset")
    validate_sql("WITH t AS (SELECT * FROM top500) SELECT count(*) FROM t")


def test_extract_sql():
    assert extract_sql("```sql\nSELECT 1;\n``` and more") == "SELECT 1;"
    assert extract_sql("Here you go: SELECT 2; DROP TABLE x;") == "SELECT 2;"


@pytest.mark.parametrize("a,b", [
    ("Microsoft bugs in May 2026", "Microsoft bugs in June 2026"), ("top 3 CVEs", "top 5 CVEs"),
    ("with exploit code", "without exploit code"), ("rank of CVE-2026-1111", "rank of CVE-2026-2222"),
    ("findings on isolated assets", "findings on internal assets"), ("Act now findings", "Act soon findings")])
def test_entity_guard_separates_near_identical_questions(a, b):
    assert entities(a) != entities(b)


def test_entity_guard_names_and_short_names():
    names = ["Apache", "IT"]
    assert entities("What should IT fix?", names)["names"] == ["it"]
    assert entities("What should it fix?", names)["names"] == []
    assert entities("how many apache bugs", names)["names"] == ["apache"]


def test_count_wording_is_treated_the_same():
    assert entities("count the findings") == entities("how many the findings")


def test_dropped_filters_are_caught():
    from src.ask_the_data.ask import missing_conditions
    names = ["Apache", "IT", "Microsoft", "Microsoft Exchange Server"]
    e = entities("Which Apache vulnerabilities in the top 20 have a Nuclei template?", names)
    assert set(missing_conditions(e, "SELECT cve_id FROM top500 WHERE rank <= 20 AND nuclei")) == {"apache"}
    assert missing_conditions(e, "SELECT cve_id FROM top500 WHERE rank <= 20 AND nuclei AND vendor ILIKE '%apache%'") == []
    e = entities("Which internal assets hold sensitive data?", names)
    assert set(missing_conditions(e, "SELECT asset FROM assets WHERE data_value = 'high'")) == {"internal"}
    e = entities("Which assets are affected by Microsoft Exchange Server?", names)
    assert missing_conditions(e, "SELECT asset FROM asset_findings WHERE software ILIKE '%exchange%'") == []
    e = entities("How many vulnerabilities in the top 500 have a GitHub proof of concept?", names)
    assert missing_conditions(e, "SELECT count(*) FROM top500 WHERE github_poc") == []


def test_long_results_are_summarised_from_every_row():
    from src.ask_the_data.ask import Asker
    a = Asker.__new__(Asker)
    a.complete = lambda *_: pytest.fail("a long result must not go to the model")
    rows = [["a", "CVE-1"]] * 10 + [["b", "CVE-2"]] * 5 + [["late", "CVE-3"]] * 3
    text = a.word_answer("Which assets?", ["asset", "cve_id"], rows)
    assert text == "18 results across a, b and late. All rows are under Show the SQL and data."
    many = [[f"CVE-{i}"] for i in range(40)]
    assert a.word_answer("Which CVEs?", ["cve_id"], many) == "40 results, shown below."
