#include "core/project.hpp"
#include <sqlite3.h>
#include <cstring>

namespace aida {

static bool exec_sql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    if (err) sqlite3_free(err);
    return rc == SQLITE_OK;
}

bool save_project(const BinaryImage& img, const std::string& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) return false;

    exec_sql(db, "BEGIN TRANSACTION");

    exec_sql(db, R"(
        CREATE TABLE IF NOT EXISTS meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    )");

    exec_sql(db, R"(
        CREATE TABLE IF NOT EXISTS functions (
            addr INTEGER PRIMARY KEY,
            end_addr INTEGER,
            name TEXT,
            user_named INTEGER DEFAULT 0,
            is_import INTEGER DEFAULT 0,
            is_export INTEGER DEFAULT 0
        )
    )");

    exec_sql(db, R"(
        CREATE TABLE IF NOT EXISTS user_names (
            addr INTEGER PRIMARY KEY,
            name TEXT
        )
    )");

    exec_sql(db, R"(
        CREATE TABLE IF NOT EXISTS user_comments (
            addr INTEGER PRIMARY KEY,
            comment TEXT
        )
    )");

    // meta
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", -1, &stmt, nullptr);
    auto put_meta = [&](const char* k, const std::string& v) {
        sqlite3_bind_text(stmt, 1, k, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, v.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    };
    put_meta("binary_path", img.path);
    put_meta("format", std::to_string(static_cast<int>(img.format)));
    put_meta("arch", std::to_string(static_cast<int>(img.arch)));
    put_meta("base", std::to_string(img.base));
    put_meta("entry", std::to_string(img.entry));
    sqlite3_finalize(stmt);

    // functions
    exec_sql(db, "DELETE FROM functions");
    sqlite3_prepare_v2(db,
        "INSERT INTO functions(addr,end_addr,name,user_named,is_import,is_export) VALUES(?,?,?,?,?,?)",
        -1, &stmt, nullptr);
    for (auto& [addr, f] : img.functions) {
        sqlite3_bind_int64(stmt, 1, addr);
        sqlite3_bind_int64(stmt, 2, f.end_addr);
        sqlite3_bind_text(stmt, 3, f.name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, f.user_named ? 1 : 0);
        sqlite3_bind_int(stmt, 5, f.is_import ? 1 : 0);
        sqlite3_bind_int(stmt, 6, f.is_export ? 1 : 0);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    // user names
    exec_sql(db, "DELETE FROM user_names");
    sqlite3_prepare_v2(db, "INSERT INTO user_names(addr,name) VALUES(?,?)", -1, &stmt, nullptr);
    for (auto& [addr, name] : img.user_names) {
        sqlite3_bind_int64(stmt, 1, addr);
        sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    // user comments
    exec_sql(db, "DELETE FROM user_comments");
    sqlite3_prepare_v2(db, "INSERT INTO user_comments(addr,comment) VALUES(?,?)", -1, &stmt, nullptr);
    for (auto& [addr, comment] : img.user_comments) {
        sqlite3_bind_int64(stmt, 1, addr);
        sqlite3_bind_text(stmt, 2, comment.c_str(), -1, SQLITE_TRANSIENT);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    exec_sql(db, "COMMIT");
    sqlite3_close(db);
    return true;
}

bool load_project(BinaryImage& img, const std::string& path) {
    sqlite3* db = nullptr;
    if (sqlite3_open_v2(path.c_str(), &db, SQLITE_OPEN_READONLY, nullptr) != SQLITE_OK)
        return false;

    // functions
    sqlite3_stmt* stmt = nullptr;
    sqlite3_prepare_v2(db, "SELECT addr,end_addr,name,user_named,is_import,is_export FROM functions",
                        -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Function f;
        f.addr = sqlite3_column_int64(stmt, 0);
        f.end_addr = sqlite3_column_int64(stmt, 1);
        const char* n = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        if (n) f.name = n;
        f.user_named = sqlite3_column_int(stmt, 3) != 0;
        f.is_import = sqlite3_column_int(stmt, 4) != 0;
        f.is_export = sqlite3_column_int(stmt, 5) != 0;
        img.functions[f.addr] = std::move(f);
    }
    sqlite3_finalize(stmt);

    // user names
    sqlite3_prepare_v2(db, "SELECT addr,name FROM user_names", -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t addr = sqlite3_column_int64(stmt, 0);
        const char* n = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (n) img.user_names[addr] = n;
    }
    sqlite3_finalize(stmt);

    // user comments
    sqlite3_prepare_v2(db, "SELECT addr,comment FROM user_comments", -1, &stmt, nullptr);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        uint64_t addr = sqlite3_column_int64(stmt, 0);
        const char* c = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        if (c) img.user_comments[addr] = c;
    }
    sqlite3_finalize(stmt);

    sqlite3_close(db);
    return true;
}

}
