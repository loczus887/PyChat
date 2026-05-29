import pytest
from db.users import UserDB


@pytest.fixture
def db():
    database = UserDB(":memory:")
    database.init()
    yield database
    database.close()


class TestInit:
    def test_init_creates_table(self, db):
        assert not db.user_exists("alice")

    def test_close_and_reinit(self):
        database = UserDB(":memory:")
        database.init()
        database.close()
        assert database._conn is None


class TestCreateUser:
    def test_creates_user(self, db):
        assert db.create_user("alice", "hash123") is True
        assert db.user_exists("alice")

    def test_duplicate_username_returns_false(self, db):
        db.create_user("alice", "hash1")
        assert db.create_user("alice", "hash2") is False

    def test_default_role_is_user(self, db):
        db.create_user("alice", "hash")
        assert db.get_role("alice") == "user"

    def test_custom_role(self, db):
        db.create_user("admin", "hash", role="admin")
        assert db.get_role("admin") == "admin"

    def test_multiple_users(self, db):
        db.create_user("alice", "h1")
        db.create_user("bob", "h2")
        assert db.user_exists("alice")
        assert db.user_exists("bob")


class TestGetPasswordHash:
    def test_returns_stored_hash(self, db):
        db.create_user("alice", "secret_hash")
        assert db.get_password_hash("alice") == "secret_hash"

    def test_returns_none_for_unknown_user(self, db):
        assert db.get_password_hash("nobody") is None

    def test_hash_preserved_exactly(self, db):
        bcrypt_like = "$2b$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234"
        db.create_user("alice", bcrypt_like)
        assert db.get_password_hash("alice") == bcrypt_like


class TestUserExists:
    def test_existing_user(self, db):
        db.create_user("alice", "h")
        assert db.user_exists("alice") is True

    def test_missing_user(self, db):
        assert db.user_exists("ghost") is False


class TestGetRole:
    def test_known_user(self, db):
        db.create_user("alice", "h")
        assert db.get_role("alice") == "user"

    def test_unknown_user_returns_none(self, db):
        assert db.get_role("ghost") is None


class TestDeleteUser:
    def test_deletes_existing_user(self, db):
        db.create_user("alice", "h")
        assert db.delete_user("alice") is True
        assert not db.user_exists("alice")

    def test_delete_nonexistent_returns_false(self, db):
        assert db.delete_user("ghost") is False

    def test_delete_does_not_affect_others(self, db):
        db.create_user("alice", "h1")
        db.create_user("bob", "h2")
        db.delete_user("alice")
        assert db.user_exists("bob")
