#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <memory>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <array>
#include <fstream>
#include <algorithm>
#include <cctype>

//  SHA-256 
namespace sha256_impl {

static const std::array<uint32_t, 64> K = {{
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
}};

static inline uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t ch(uint32_t e, uint32_t f, uint32_t g)  { return (e & f) ^ (~e & g); }
static inline uint32_t maj(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
static inline uint32_t ep0(uint32_t a) { return rotr(a,2)  ^ rotr(a,13) ^ rotr(a,22); }
static inline uint32_t ep1(uint32_t e) { return rotr(e,6)  ^ rotr(e,11) ^ rotr(e,25); }
static inline uint32_t sig0(uint32_t x){ return rotr(x,7)  ^ rotr(x,18) ^ (x >> 3);  }
static inline uint32_t sig1(uint32_t x){ return rotr(x,17) ^ rotr(x,19) ^ (x >> 10); }

std::string compute(const std::string& input) {
    // Initial hash values (first 32 bits of fractional parts of sqrt of first 8 primes)
    uint32_t h[8] = {
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
        0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19
    };

    // Pre-processing: padding
    std::vector<uint8_t> msg(input.begin(), input.end());
    uint64_t bit_len = msg.size() * 8ULL;
    msg.push_back(0x80);
    while (msg.size() % 64 != 56) msg.push_back(0x00);
    for (int i = 7; i >= 0; --i)
        msg.push_back(static_cast<uint8_t>((bit_len >> (i * 8)) & 0xFF));

    // Process each 512-bit chunk
    for (size_t chunk = 0; chunk < msg.size(); chunk += 64) {
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (static_cast<uint32_t>(msg[chunk + i*4])     << 24) |
                   (static_cast<uint32_t>(msg[chunk + i*4 + 1]) << 16) |
                   (static_cast<uint32_t>(msg[chunk + i*4 + 2]) <<  8) |
                   (static_cast<uint32_t>(msg[chunk + i*4 + 3]));
        for (int i = 16; i < 64; ++i)
            w[i] = sig1(w[i-2]) + w[i-7] + sig0(w[i-15]) + w[i-16];

        uint32_t a=h[0],b=h[1],c=h[2],d=h[3],
                 e=h[4],f=h[5],g=h[6],hh=h[7];

        for (int i = 0; i < 64; ++i) {
            uint32_t t1 = hh + ep1(e) + ch(e,f,g) + K[i] + w[i];
            uint32_t t2 = ep0(a) + maj(a,b,c);
            hh=g; g=f; f=e; e=d+t1;
            d=c;  c=b; b=a; a=t1+t2;
        }
        h[0]+=a; h[1]+=b; h[2]+=c; h[3]+=d;
        h[4]+=e; h[5]+=f; h[6]+=g; h[7]+=hh;
    }

    std::ostringstream oss;
    for (int i = 0; i < 8; ++i)
        oss << std::hex << std::setw(8) << std::setfill('0') << h[i];
    return oss.str();
}

} // namespace sha256_impl
const std::string SALT = "TUBESPSDA_SECURE_SALT_2024";

std::string hash_sha256(const std::string& input) {
    // HMAC-like: SHA256(salt + SHA256(input + salt))
    // Lebih kuat dari double-std::hash sebelumnya
    std::string inner = sha256_impl::compute(input + SALT);
    return sha256_impl::compute(SALT + inner);
}

// ============================================================
//  Utility — trim & secure_compare (dipakai di config & auth)
// ============================================================
std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    size_t end   = s.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : s.substr(start, end - start + 1);
}

bool secure_compare(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    volatile int diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= (a[i] ^ b[i]);
    return diff == 0;
}

const std::string CONFIG_FILE = "config.dat";
const std::string ADMIN_USER  = "admin";   // username tetap "admin"

struct Config {
    bool        exists      = false;
    std::string pass_hash;
};

Config load_config() {
    Config cfg;
    std::ifstream f(CONFIG_FILE);
    if (!f) return cfg;          // file belum ada → first run
    std::string line1, line2;
    if (!std::getline(f, line1)) return cfg;
    if (!std::getline(f, line2)) return cfg;
    // baris 1 harus "admin", baris 2 hash 64-char hex
    if (trim(line1) != ADMIN_USER) return cfg;
    if (trim(line2).size() != 64)  return cfg;
    cfg.exists    = true;
    cfg.pass_hash = trim(line2);
    return cfg;
}

bool save_config(const std::string& pass_plain) {
    std::ofstream f(CONFIG_FILE);
    if (!f) return false;
    f << ADMIN_USER << '\n' << hash_sha256(pass_plain) << '\n';
    return true;
}

bool authenticate(const std::string& user, const std::string& pass,
                  const std::string& stored_hash) {
    return secure_compare(trim(user), ADMIN_USER) &&
           secure_compare(hash_sha256(pass), stored_hash);
}

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_base.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>

using namespace ftxui;

enum class AppState { SETUP, LOGIN, LOCKED, MENU, ADD_PLAYER, VIEW_BOARD, EDIT_PLAYER, CREDITS };

struct Player {
    std::string name;
    long long   score;
};

void insertion_sort(std::vector<Player>& players) {
    for (size_t i = 1; i < players.size(); ++i) {
        Player key = players[i];
        int j = static_cast<int>(i) - 1;
        while (j >= 0 && players[j].score < key.score) {
            players[j + 1] = players[j];
            --j;
        }
        players[j + 1] = key;
    }
}

const std::string DATA_FILE = "leaderboard.csv";

void save_players(const std::vector<Player>& players) {
    std::ofstream f(DATA_FILE);
    if (!f) return;
    for (const auto& p : players) {
        bool has_comma = p.name.find(',') != std::string::npos;
        if (has_comma) {
            std::string escaped;
            for (char c : p.name) {
                if (c == '"') escaped += "\"\"";
                else escaped += c;
            }
            f << '"' << escaped << '"' << ',' << p.score << '\n';
        } else {
            f << p.name << ',' << p.score << '\n';
        }
    }
}

std::vector<Player> load_players() {
    std::vector<Player> result;
    std::ifstream f(DATA_FILE);
    if (!f) return result;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty()) continue;
        std::string name, score_str;
        if (!line.empty() && line[0] == '"') {
            size_t pos = 1;
            while (pos < line.size() && line[pos] != '"') {
                if (line[pos] == '"' && pos+1 < line.size() && line[pos+1] == '"') {
                    name += '"'; pos += 2;
                } else {
                    name += line[pos++];
                }
            }
            size_t comma = line.find(',', pos);
            if (comma == std::string::npos) continue;
            score_str = line.substr(comma + 1);
        } else {
            size_t comma = line.rfind(',');
            if (comma == std::string::npos) continue;
            name      = line.substr(0, comma);
            score_str = line.substr(comma + 1);
        }
        name      = trim(name);
        score_str = trim(score_str);
        if (name.empty() || score_str.empty()) continue;
        bool valid = true;
        for (char c : score_str)
            if (!std::isdigit(static_cast<unsigned char>(c))) { valid = false; break; }
        if (!valid) continue;
        try { result.push_back({ name, std::stoll(score_str) }); } catch (...) {}
    }
    return result;
}

// Cek duplikat nama (case-insensitive)
bool name_exists(const std::vector<Player>& players, const std::string& name) {
    std::string ln = name;
    std::transform(ln.begin(), ln.end(), ln.begin(),
        [](unsigned char c){ return std::tolower(c); });
    for (const auto& p : players) {
        std::string lp = p.name;
        std::transform(lp.begin(), lp.end(), lp.begin(),
            [](unsigned char c){ return std::tolower(c); });
        if (lp == ln) return true;
    }
    return false;
}

int main() {
    const int MAX_ATTEMPTS = 5;
    const int LOCKOUT_SECS = 30;

    // Load config — tentukan apakah perlu SETUP atau langsung LOGIN
    Config cfg = load_config();
    AppState state = cfg.exists ? AppState::LOGIN : AppState::SETUP;
    std::string error_msg;
    std::string input_error;

    std::string username, password;
    int attempts = MAX_ATTEMPTS;
    std::chrono::steady_clock::time_point lockout_until;

    // Load data dari file saat startup
    std::vector<Player> players = load_players();
    bool sorted = false;
    std::string new_name, new_score_str;

    // State untuk edit/hapus
    int    selected_idx   = -1;
    std::string edit_name, edit_score_str;
    bool   confirm_delete = false;
    bool   confirm_reset  = false;

    // Setup wizard state
    std::string setup_pass1, setup_pass2;
    std::string setup_error;

    auto screen = ScreenInteractive::Fullscreen();

    // STYLES
    auto btn_opt = ButtonOption::Animated();
    btn_opt.transform = [](const EntryState& s) {
        auto element = text(s.label);
        if (s.focused) {
            element |= inverted;
            element |= bold;
        }
        return element | center | border;
    };

    // LOGIN inputs
    Component input_username = Input(&username, "username");
    InputOption pass_opt;
    pass_opt.password = true;
    Component input_password = Input(&password, "password", pass_opt);

    // SETUP wizard inputs
    InputOption setup_opt;
    setup_opt.password = true;
    Component input_setup_pass1 = Input(&setup_pass1, "password baru", setup_opt);
    Component input_setup_pass2 = Input(&setup_pass2, "konfirmasi password", setup_opt);

    auto on_setup = [&] {
        setup_error.clear();
        if (setup_pass1.empty()) { setup_error = "Password tidak boleh kosong."; return; }
        if (setup_pass1.size() < 6) { setup_error = "Password minimal 6 karakter."; return; }
        if (setup_pass1 != setup_pass2) { setup_error = "Konfirmasi password tidak cocok."; return; }
        if (!save_config(setup_pass1)) { setup_error = "Gagal menyimpan config.dat!"; return; }
        cfg = load_config();   // reload supaya pass_hash terisi
        setup_pass1.clear();
        setup_pass2.clear();
        state = AppState::LOGIN;
        error_msg = "Setup selesai! Silakan login.";
    };

    Component btn_setup_confirm = Button("  Simpan & Lanjut  ", on_setup, btn_opt);
    Component setup_container = Container::Vertical({
        input_setup_pass1,
        input_setup_pass2,
        btn_setup_confirm,
    });

    auto on_login = [&] {
        error_msg.clear();
        if (state == AppState::LOCKED) {
            auto now = std::chrono::steady_clock::now();
            if (now < lockout_until) {
                auto secs = std::chrono::duration_cast<std::chrono::seconds>(
                    lockout_until - now).count();
                error_msg = "Locked. Try again in " + std::to_string(secs) + "s.";
                return;
            }
            state    = AppState::LOGIN;
            attempts = MAX_ATTEMPTS;
        }
        if (trim(username).empty()) { error_msg = "Username cannot be blank."; return; }
        if (password.empty())        { error_msg = "Password cannot be blank.";  return; }
        if (authenticate(username, password, cfg.pass_hash)) {
            state = AppState::MENU;
        } else {
            --attempts;
            password.clear();
            if (attempts <= 0) {
                state = AppState::LOCKED;
                lockout_until = std::chrono::steady_clock::now() +
                                std::chrono::seconds(LOCKOUT_SECS);
                error_msg = "Too many failures. Locked for " +
                            std::to_string(LOCKOUT_SECS) + " seconds.";
            } else {
                error_msg = "Invalid credentials. " +
                            std::to_string(attempts) + " attempt(s) remaining.";
            }
        }
    };

    Component login_button = Button("  Login  ", on_login, btn_opt);
    Component login_container = Container::Vertical({
        input_username,
        input_password,
        login_button,
    });

    // MENU buttons
    Component btn_add_player = Button(" Add Player ", [&] {
        input_error.clear();
        new_name.clear();
        new_score_str.clear();
        state = AppState::ADD_PLAYER;
    }, btn_opt);
    Component btn_view = Button(" Leaderboard ", [&] {
        selected_idx   = -1;
        confirm_delete = false;
        confirm_reset  = false;
        state = AppState::VIEW_BOARD;
    }, btn_opt);
    Component btn_sort = Button(" Sort Scores ", [&] {
        if (players.empty()) { error_msg = "No players to sort."; return; }
        insertion_sort(players);
        sorted = true;
        save_players(players);  // Simpan urutan baru
        error_msg.clear();
    }, btn_opt);
    Component btn_credits = Button(" Credits ", [&] {
        state = AppState::CREDITS;
    }, btn_opt);

    auto btn_danger_opt = btn_opt;
    btn_danger_opt.transform = [](const EntryState& s) {
        auto element = text(s.label);
        if (s.focused) {
            element |= inverted;
            element |= bold;
        }
        return element | center | border | color(Color::RedLight);
    };

    Component btn_logout = Button("  Logout  ", [&] {
        state    = AppState::LOGIN;
        username.clear();
        password.clear();
        error_msg.clear();
        input_error.clear();
        attempts = MAX_ATTEMPTS;
        // Data player TIDAK dihapus saat logout — tersimpan di file
    }, btn_danger_opt);

    Component menu_actions = Container::Horizontal({
        btn_add_player,
        btn_view,
        btn_sort,
        btn_credits,
    });
    Component menu_container = Container::Vertical({
        menu_actions,
        btn_logout,
    });

    // ADD PLAYER inputs
    Component input_name  = Input(&new_name,      "Player name");
    Component input_score = Input(&new_score_str, "Score (number)");

    auto on_add_player = [&] {
        input_error.clear();
        std::string n = trim(new_name);
        std::string s = trim(new_score_str);
        if (n.empty()) { input_error = "Name cannot be blank.";        return; }
        if (s.empty()) { input_error = "Score cannot be blank.";       return; }
        for (char c : s) {
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                input_error = "Score must be a whole number.";
                return;
            }
        }
        if (s.size() > 18) {
            input_error = "Score too long (max 18 digit).";
            return;
        }
        long long score_val = std::stoll(s);
        if (score_val <= 0) {
            input_error = "Score must be greater than 0.";
            return;
        }
        if (name_exists(players, n)) {
            input_error = "Player \"" + n + "\" already exists!";
            return;
        }
        players.push_back({ n, score_val });
        sorted = false;
        save_players(players);   // Simpan ke file setiap kali ada penambahan
        new_name.clear();
        new_score_str.clear();
        input_error = "Player added & saved!";
    };

    Component btn_confirm_add = Button("  Add  ",  on_add_player, btn_opt);
    Component btn_back_add    = Button("  Back  ", [&] {
        input_error.clear();
        state = AppState::MENU;
    }, btn_opt);

    Component add_container = Container::Vertical({
        input_name,
        input_score,
        Container::Horizontal({ btn_confirm_add, btn_back_add }),
    });

    // EDIT PLAYER inputs
    Component input_edit_name  = Input(&edit_name,       "Player name");
    Component input_edit_score = Input(&edit_score_str,  "Score (number)");

    auto on_edit_player = [&] {
        input_error.clear();
        if (selected_idx < 0 || selected_idx >= (int)players.size()) return;
        std::string n = trim(edit_name);
        std::string s = trim(edit_score_str);
        if (n.empty()) { input_error = "Name cannot be blank.";  return; }
        if (s.empty()) { input_error = "Score cannot be blank."; return; }
        for (char c : s)
            if (!std::isdigit(static_cast<unsigned char>(c))) {
                input_error = "Score must be a whole number."; return;
            }
        if (s.size() > 18) { input_error = "Score too long (max 18 digit)."; return; }
        long long score_val = std::stoll(s);
        if (score_val <= 0) { input_error = "Score must be greater than 0."; return; }

        // Cek duplikat nama — kecuali nama player itu sendiri
        std::string ln = n;
        std::transform(ln.begin(), ln.end(), ln.begin(),
            [](unsigned char c){ return std::tolower(c); });
        for (int i = 0; i < (int)players.size(); ++i) {
            if (i == selected_idx) continue;
            std::string lp = players[i].name;
            std::transform(lp.begin(), lp.end(), lp.begin(),
                [](unsigned char c){ return std::tolower(c); });
            if (lp == ln) { input_error = "Name already used by another player!"; return; }
        }

        players[selected_idx].name  = n;
        players[selected_idx].score = score_val;
        sorted = false;
        save_players(players);
        input_error = "Player updated!";
    };

    Component btn_confirm_edit = Button("  Save  ", on_edit_player, btn_opt);
    Component btn_back_edit    = Button("  Back  ", [&] {
        input_error.clear();
        confirm_delete = false;
        state = AppState::VIEW_BOARD;
    }, btn_opt);

    Component edit_container = Container::Vertical({
        input_edit_name,
        input_edit_score,
        Container::Horizontal({ btn_confirm_edit, btn_back_edit }),
    });

    // VIEW BOARD back button
    Component btn_back_view = Button("  Back  ", [&] {
        state = AppState::MENU;
    }, btn_opt);
    Component view_container = Container::Vertical({ btn_back_view });

    // CREDITS back button
    Component btn_back_credits = Button("  Back  ", [&] {
        state = AppState::MENU;
    }, btn_opt);
    Component credits_container = Container::Vertical({ btn_back_credits });

    // LOCKED placeholder
    Component locked_container = Container::Vertical({});

    // Root switchable container
    int tab_index = 0;
    Component root = Container::Tab({
        setup_container,   // 0 = SETUP
        login_container,   // 1 = LOGIN
        locked_container,  // 2 = LOCKED
        menu_container,    // 3 = MENU
        add_container,     // 4 = ADD_PLAYER
        view_container,    // 5 = VIEW_BOARD
        edit_container,    // 6 = EDIT_PLAYER
        credits_container, // 7 = CREDITS
    }, &tab_index);

    // Renderer
    auto renderer = Renderer(root, [&]() -> Element {
        tab_index = static_cast<int>(state);

        // SETUP (first run)
        if (state == AppState::SETUP) {
            Elements rows;
            rows.push_back(
                text("Selamat datang di Hall of Fame!") | bold | center | color(Color::Cyan)
            );
            rows.push_back(separatorEmpty());
            rows.push_back(
                text("Ini adalah pertama kali program dijalankan.") | dim | center
            );
            rows.push_back(
                text("Buat password admin untuk melanjutkan.") | dim | center
            );
            rows.push_back(separator());
            rows.push_back(hbox(text(" Username      : "),
                text("admin") | bold | color(Color::GreenLight)));
            rows.push_back(separatorEmpty());
            rows.push_back(hbox(text(" Password Baru : "), input_setup_pass1->Render()));
            rows.push_back(separatorEmpty());
            rows.push_back(hbox(text(" Konfirmasi    : "), input_setup_pass2->Render()));
            rows.push_back(separator());
            if (!setup_error.empty()) {
                rows.push_back(text(" " + setup_error) | color(Color::Red) | center);
                rows.push_back(separatorEmpty());
            }
            rows.push_back(btn_setup_confirm->Render() | center);
            rows.push_back(separatorEmpty());
            rows.push_back(
                text("Password disimpan sebagai hash SHA-256 di config.dat")
                    | dim | center
            );
            return center(
                window(text(" Setup Awal — Hall of Fame ") | bold | center,
                    vbox(std::move(rows))
                ) | clear_under | size(WIDTH, GREATER_THAN, 55)
            );
        }

        // LOCKED
        if (state == AppState::LOCKED) {
            return center(
                window(text(" Access Denied ") | bold,
                    vbox({
                        text("Account locked.") | center | color(Color::Red),
                        text(error_msg.empty() ? "Too many failed attempts." : error_msg)
                            | center | color(Color::RedLight),
                        separatorEmpty(),
                        text("Press Esc to quit.") | dim | center,
                    })
                ) | color(Color::Red)
            );
        }

        // LOGIN
        if (state == AppState::LOGIN) {
            Elements rows;
            rows.push_back(hbox(text(" Username : "), input_username->Render()));
            rows.push_back(separatorEmpty());
            rows.push_back(hbox(text(" Password : "), input_password->Render()));
            rows.push_back(separator());
            if (!error_msg.empty()) {
                bool is_success = (error_msg.find("Setup selesai") != std::string::npos);
                rows.push_back(text(" " + error_msg)
                    | color(is_success ? Color::GreenLight : Color::Red) | center);
                rows.push_back(separatorEmpty());
            }
            rows.push_back(login_button->Render());
            rows.push_back(separatorEmpty());
            Color ac = (attempts > MAX_ATTEMPTS / 2)
                ? Color::GreenLight : (attempts > 1 ? Color::Yellow : Color::Red);
            rows.push_back(
                text("Attempts remaining: " + std::to_string(attempts))
                    | color(ac) | center
            );
            return center(
                window(text("Hall Of Fame Login ") | bold | center,
                    vbox(std::move(rows))
                ) | clear_under
            );
        }

        // MAIN MENU
        if (state == AppState::MENU) {
            Elements rows;
            rows.push_back(
                hbox({
                    text("Logged in as: ") | dim,
                    text(trim(username)) | bold | color(Color::GreenLight),
                }) | center
            );
            rows.push_back(separator());
            if (!error_msg.empty()) {
                rows.push_back(text(" " + error_msg) | color(Color::Yellow) | center);
                rows.push_back(separatorEmpty());
            }
            rows.push_back(
                hbox({
                    btn_add_player->Render(),
                    separatorEmpty(),
                    btn_view->Render(),
                    separatorEmpty(),
                    btn_sort->Render(),
                    separatorEmpty(),
                    btn_credits->Render(),
                }) | center
            );
            rows.push_back(separator());
            rows.push_back(btn_logout->Render() | center);

            return center(
                window(text(" Main Menu ") | bold | center,
                    vbox(std::move(rows))
                ) | size(WIDTH, GREATER_THAN, 50)
            );
        }

        if (state == AppState::ADD_PLAYER) {
            Elements rows;
            rows.push_back(hbox(text(" Name  : "), input_name->Render()));
            rows.push_back(separatorEmpty());
            rows.push_back(hbox(text(" Score : "), input_score->Render()));
            rows.push_back(separator());
            if (!input_error.empty()) {
                Color c = (input_error == "Player added & saved!") ? Color::GreenLight : Color::Red;
                rows.push_back(text(" " + input_error) | color(c) | center);
                rows.push_back(separatorEmpty());
            }
            rows.push_back(
                hbox({
                    btn_confirm_add->Render(),
                    btn_back_add->Render(),
                }) | center
            );
            return center(
                window(text(" Add Player ") | bold | center,
                    vbox(std::move(rows))
                ) | clear_under
            );
        }

        // CREDITS
        if (state == AppState::CREDITS) {
            Elements rows;
            rows.push_back(text("Kelompok 7 TUBES PSDA") | bold | center | color(Color::Cyan));
            rows.push_back(separator());
            rows.push_back(hbox(text(" 1. "), text("Abdul Vaiz Vahry Iskandar ") | flex, text("G1A025063 ")));
            rows.push_back(hbox(text(" 2. "), text("Nadhif Arwendo ") | flex, text("G1A025077 ")));
            rows.push_back(hbox(text(" 3. "), text("Ivo Indah Ghazeta ") | flex, text("G1A025087 ")));
            rows.push_back(separator());
            rows.push_back(btn_back_credits->Render() | center);
            return center(
                window(text(" Team Credits ") | bold | center,
                    vbox(std::move(rows))
                ) | clear_under | size(WIDTH, GREATER_THAN, 40)
            );
        }

        // EDIT PLAYER
        if (state == AppState::EDIT_PLAYER) {
            Elements rows;
            if (selected_idx >= 0 && selected_idx < (int)players.size())
                rows.push_back(
                    hbox({ text(" Editing: ") | dim,
                           text(players[selected_idx].name) | bold | color(Color::Cyan) })
                    | center
                );
            rows.push_back(separatorEmpty());
            rows.push_back(hbox(text(" Name  : "), input_edit_name->Render()));
            rows.push_back(separatorEmpty());
            rows.push_back(hbox(text(" Score : "), input_edit_score->Render()));
            rows.push_back(separator());
            if (!input_error.empty()) {
                Color c = (input_error == "Player updated!") ? Color::GreenLight : Color::Red;
                rows.push_back(text(" " + input_error) | color(c) | center);
                rows.push_back(separatorEmpty());
            }
            rows.push_back(
                hbox({ btn_confirm_edit->Render(), btn_back_edit->Render() }) | center
            );
            return center(
                window(text(" Edit Player ") | bold | center,
                    vbox(std::move(rows))
                ) | clear_under
            );
        }

        // VIEW LEADERBOARD
        Elements rows;

        // === CONFIRM DELETE DIALOG ===
        if (confirm_delete && selected_idx >= 0 && selected_idx < (int)players.size()) {
            rows.push_back(
                vbox({
                    text("Hapus player ini?") | bold | center,
                    separatorEmpty(),
                    text("  " + players[selected_idx].name +
                         "  (score: " + std::to_string(players[selected_idx].score) + ")")
                        | color(Color::Yellow) | center,
                    separatorEmpty(),
                    hbox({
                        // Tombol konfirmasi inline via lambda — dibuat saat render
                        text("[ Ya, Hapus ]") | color(Color::Red) | bold | center | border,
                        separatorEmpty(),
                        text("[  Batal  ]") | center | border,
                    }) | center,
                    separatorEmpty(),
                    text("Tekan Y = hapus   N/Esc = batal") | dim | center,
                })
            );
            rows.push_back(separatorEmpty());
            rows.push_back(btn_back_view->Render() | center);
            return center(
                window(text(" Konfirmasi Hapus ") | bold | center | color(Color::Red),
                    vbox(std::move(rows))
                ) | clear_under
            );
        }

        // === CONFIRM RESET DIALOG ===
        if (confirm_reset) {
            rows.push_back(
                vbox({
                    text("Reset SEMUA data leaderboard?") | bold | center | color(Color::Red),
                    separatorEmpty(),
                    text("Tindakan ini tidak dapat dibatalkan!") | dim | center,
                    separatorEmpty(),
                    text("Tekan Y = reset semua   N/Esc = batal") | dim | center,
                })
            );
            rows.push_back(separatorEmpty());
            rows.push_back(btn_back_view->Render() | center);
            return center(
                window(text(" Konfirmasi Reset ") | bold | center | color(Color::Red),
                    vbox(std::move(rows))
                ) | clear_under
            );
        }

        // === TABEL LEADERBOARD ===
        if (players.empty()) {
            rows.push_back(text("No players yet.") | dim | center);
        } else {
            std::vector<std::vector<Element>> table_data;
            table_data.push_back({
                text(" # ") | bold | center,
                text(" Player Name ") | bold | center,
                text(" Score ") | bold | center,
                text(" Aksi ") | bold | center,
            });

            for (size_t i = 0; i < players.size(); ++i) {
                Color rc = Color::Default;
                if (sorted) {
                    if      (i == 0) rc = Color::GreenLight;
                    else if (i == 1) rc = Color::BlueLight;
                    else if (i == 2) rc = Color::RedLight;
                }
                bool is_sel = ((int)i == selected_idx);
                table_data.push_back({
                    text(" " + std::to_string(i + 1) + " ") | color(rc) | center,
                    text(" " + players[i].name + " ")        | color(rc) | (is_sel ? bold : nothing),
                    text(" " + std::to_string(players[i].score) + " ") | color(rc) | align_right,
                    text(is_sel ? " [selected] " : " - ") | dim | center,
                });
            }

            auto lb_table = Table(table_data);
            lb_table.SelectAll().Border(LIGHT);
            lb_table.SelectRow(0).Decorate(bold);
            lb_table.SelectRow(0).SeparatorVertical(LIGHT);
            lb_table.SelectRow(0).Border(DOUBLE);
            lb_table.SelectAll().SeparatorVertical(LIGHT);
            rows.push_back(lb_table.Render() | center);
        }

        rows.push_back(separatorEmpty());

        // Instruksi navigasi
        if (!players.empty()) {
            rows.push_back(
                hbox({
                    text(" ↑↓ pilih row") | dim,
                    text("  |  ") | dim,
                    text("E") | bold | color(Color::Cyan),
                    text(" edit") | dim,
                    text("  |  ") | dim,
                    text("D") | bold | color(Color::Red),
                    text(" hapus") | dim,
                    text("  |  ") | dim,
                    text("R") | bold | color(Color::Yellow),
                    text(" reset semua") | dim,
                }) | center
            );
            rows.push_back(separatorEmpty());
            if (selected_idx >= 0 && selected_idx < (int)players.size()) {
                rows.push_back(
                    text("Dipilih: " + players[selected_idx].name)
                        | color(Color::Cyan) | center
                );
                rows.push_back(separatorEmpty());
            }
        }

        rows.push_back(btn_back_view->Render() | center);

        return center(
            window(text(" Leaderboard ") | bold | center,
                vbox(std::move(rows))
            ) | clear_under
        );
    });

    // Global events
    renderer |= CatchEvent([&](Event event) {
        tab_index = static_cast<int>(state);

        if (event == Event::Escape) {
            if (state == AppState::EDIT_PLAYER) {
                input_error.clear();
                confirm_delete = false;
                state = AppState::VIEW_BOARD;
                return true;
            }
            if (state == AppState::VIEW_BOARD) {
                if (confirm_delete || confirm_reset) {
                    confirm_delete = false;
                    confirm_reset  = false;
                    return true;
                }
                input_error.clear();
                state = AppState::MENU;
                return true;
            }
            if (state == AppState::ADD_PLAYER || state == AppState::CREDITS) {
                input_error.clear();
                state = AppState::MENU;
                return true;
            }
            // SETUP & LOGIN & LOCKED → keluar program
            screen.ExitLoopClosure()();
            return true;
        }

        if (event == Event::Return) {
            if (state == AppState::SETUP)  { on_setup();  return true; }
            if (state == AppState::LOGIN)  { on_login();  return true; }
            if (state == AppState::LOCKED) { screen.ExitLoopClosure()(); return true; }
            return false;
        }

        // ── Navigasi & aksi di layar Leaderboard ──
        if (state == AppState::VIEW_BOARD && !players.empty()) {

            // Konfirmasi delete: Y = ya, N = batal
            if (confirm_delete) {
                if (event == Event::Character('y') || event == Event::Character('Y')) {
                    if (selected_idx >= 0 && selected_idx < (int)players.size()) {
                        players.erase(players.begin() + selected_idx);
                        if (selected_idx >= (int)players.size())
                            selected_idx = (int)players.size() - 1;
                        save_players(players);
                    }
                    confirm_delete = false;
                    return true;
                }
                if (event == Event::Character('n') || event == Event::Character('N')) {
                    confirm_delete = false;
                    return true;
                }
                return false;
            }

            // Konfirmasi reset: Y = ya, N = batal
            if (confirm_reset) {
                if (event == Event::Character('y') || event == Event::Character('Y')) {
                    players.clear();
                    selected_idx = -1;
                    sorted = false;
                    save_players(players);
                    confirm_reset = false;
                    return true;
                }
                if (event == Event::Character('n') || event == Event::Character('N')) {
                    confirm_reset = false;
                    return true;
                }
                return false;
            }

            // Navigasi baris ↑↓
            if (event == Event::ArrowUp) {
                if (selected_idx > 0) --selected_idx;
                else selected_idx = 0;
                return true;
            }
            if (event == Event::ArrowDown) {
                if (selected_idx < (int)players.size() - 1) ++selected_idx;
                else selected_idx = (int)players.size() - 1;
                return true;
            }

            // E = Edit player yang dipilih
            if (event == Event::Character('e') || event == Event::Character('E')) {
                if (selected_idx >= 0 && selected_idx < (int)players.size()) {
                    edit_name      = players[selected_idx].name;
                    edit_score_str = std::to_string(players[selected_idx].score);
                    input_error.clear();
                    state = AppState::EDIT_PLAYER;
                }
                return true;
            }

            // D = Hapus player yang dipilih (minta konfirmasi)
            if (event == Event::Character('d') || event == Event::Character('D')) {
                if (selected_idx >= 0 && selected_idx < (int)players.size()) {
                    confirm_delete = true;
                }
                return true;
            }

            // R = Reset semua (minta konfirmasi)
            if (event == Event::Character('r') || event == Event::Character('R')) {
                confirm_reset = true;
                return true;
            }
        }

        return false;
    });

    screen.Loop(renderer);
    return (state == AppState::MENU) ? 0 : 1;
}