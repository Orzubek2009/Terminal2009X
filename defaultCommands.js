let defaultCommands = `
if (input === "hello") {
    say(">>hello", "gray");
    say("hello User");
} else if (input === "alert hello") {
    say(">>alert hello", "gray");
    alert("Hello");
} else if (input === "random number") {
    say(">>random number", "gray");
    say(Math.round(Math.random() * 100) + 0);
} else if (input === "/reload") {
    clear();
    intro();
} else if (input === "/clear") {
    clear();
} else if (input === "") {
    say(">>", "gray");
} else if (input === "/help") {
    say(">>/help", "gray");
    say("Available commands:\\n");
    say("hello, alert hello, random number, /help, /clear, /reload, /fake, /fake2, /hackerTyper, /mod", "lightgray");
}
`;
