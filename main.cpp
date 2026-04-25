#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <functional>
#include <memory>

#include <ftxui/component/component.hpp>
#include <ftxui/component/component_base.hpp>
#include <ftxui/component/component_options.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/dom/table.hpp>

using namespace ftxui;

enum class AppState { LOGIN, LOCKED, MENU, ADD_PLAYER, VIEW_BOARD, CREDITS };

struct Player {
    std::string name;
    long long        score;
};

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

bool authenticate(const std::string& user, const std::string& pass) {
    const std::string ADMIN_USER = "admin";
    const std::string ADMIN_PASS = "admin123";
    return secure_compare(trim(user), ADMIN_USER) &&
           secure_compare(pass, ADMIN_PASS);
}

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

int main() {
    const int MAX_ATTEMPTS = 5;
    const int LOCKOUT_SECS = 30;

    AppState state = AppState::LOGIN;
    std::string error_msg;
    std::string input_error;

    std::string username, password;
    int attempts = MAX_ATTEMPTS;
    std::chrono::steady_clock::time_point lockout_until;

    std::vector<Player> players;
    bool sorted = false;
    std::string new_name, new_score_str;

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
        if (authenticate(username, password)) {
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
        state = AppState::VIEW_BOARD;
    }, btn_opt);
    Component btn_sort = Button(" Sort Scores ", [&] {
        if (players.empty()) { error_msg = "No players to sort."; return; }
        insertion_sort(players);
        sorted = true;
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
        players.clear();
        sorted = false;
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
        players.push_back({ n, std::stoll(s) });
        sorted = false;
        new_name.clear();
        new_score_str.clear();
        input_error = "Player added!";
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
        login_container,   // 0 = LOGIN
        locked_container,  // 1 = LOCKED
        menu_container,    // 2 = MENU
        add_container,     // 3 = ADD_PLAYER
        view_container,    // 4 = VIEW_BOARD
        credits_container, // 5 = CREDITS
    }, &tab_index);

    // Renderer
    auto renderer = Renderer(root, [&]() -> Element {
        tab_index = static_cast<int>(state);

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
                rows.push_back(text(" " + error_msg) | color(Color::Red) | center);
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
                Color c = (input_error == "Player added!") ? Color::GreenLight : Color::Red;
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
            rows.push_back(text("Kelompok 7TUBES PSDA") | bold | center | color(Color::Cyan));
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

        // VIEW LEADERBOARD
        Elements rows;
        if (players.empty()) {
            rows.push_back(text("No players yet.") | dim | center);
        } else {
            std::vector<std::vector<Element>> table_data;
            
            // Header
            table_data.push_back({
                text(" # ") | bold | center,
                text(" Player Name ") | bold | center,
                text(" Score ") | bold | center,
            });

            for (size_t i = 0; i < players.size(); ++i) {
                Color rc = Color::Default;
                if (sorted) {
                    if      (i == 0) rc = Color::GreenLight;
                    else if (i == 1) rc = Color::BlueLight;
                    else if (i == 2) rc = Color::RedLight;
                }
                
                table_data.push_back({
                    text(" " + std::to_string(i + 1) + " ") | color(rc) | center,
                    text(" " + players[i].name + " ")       | color(rc),
                    text(" " + std::to_string(players[i].score) + " ") | color(rc) | align_right,
                });
            }

            auto leaderboard_table = Table(table_data);
            
            leaderboard_table.SelectAll().Border(LIGHT);
            leaderboard_table.SelectRow(0).Decorate(bold);
            leaderboard_table.SelectRow(0).SeparatorVertical(LIGHT);
            leaderboard_table.SelectRow(0).Border(DOUBLE);
            
            leaderboard_table.SelectAll().SeparatorVertical(LIGHT);

            rows.push_back(leaderboard_table.Render() | center);
        }
        rows.push_back(separatorEmpty());
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
            if (state == AppState::ADD_PLAYER || state == AppState::VIEW_BOARD || state == AppState::CREDITS) {
                input_error.clear();
                state = AppState::MENU;
                return true;
            }
            screen.ExitLoopClosure()();
            return true;
        }

        if (event == Event::Return) {
            if (state == AppState::LOGIN)  { on_login(); return true; }
            if (state == AppState::LOCKED) { screen.ExitLoopClosure()(); return true; }
            return false;
        }

        return false;
    });

    screen.Loop(renderer);
    return (state == AppState::MENU) ? 0 : 1;
}