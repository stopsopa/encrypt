#!/usr/bin/env bash
# case-016-cli_git_diff_shows_the_edited_line, Bash command line: keep an encrypted file in git: one-line diffs, and plain-text diffs with a textconv filter.
cd "$(dirname "${BASH_SOURCE[0]}")"
source ../lib/demo.sh
SSENC="$(pwd)/../../bash/bin/ssenc"   # bash + openssl, nothing to build
built "$SSENC" "(it is part of the repository)"
title "case-016-cli_git_diff_shows_the_edited_line [bash, command line]"
source ./prepare.sh

PASSWORD_FILE="$(pwd)/tmp/password.txt"
run 'cd tmp/repo'

echo "${0}: Commit the encrypted file"
run '"$SSENC" encrypt --password-file "$PASSWORD_FILE" -i settings.yml -o settings.yml.enc'
run 'git add .gitignore settings.yml.enc && git commit -q -m "settings, encrypted" && git log --oneline'

echo "${0}: Edit one line of the plain file and encrypt again to the same file"
run 'sed "s/timeout: 30/timeout: 60/" settings.yml > settings.new && mv settings.new settings.yml'
run '"$SSENC" encrypt --password-file "$PASSWORD_FILE" -i settings.yml -o settings.yml.enc'

echo "${0}: git sees exactly one changed line: you can tell WHICH line was edited without the password"
run 'git --no-pager diff --stat'
run 'git --no-pager diff'
check "one line added, one removed" '[[ "$(git diff --numstat | cut -f 1,2 | tr "\t" " ")" == "1 1" ]]'

echo "${0}: With the password, git can show the diff of the PLAIN text: a textconv filter that decrypts"
run 'echo "*.enc diff=ssenc" > .gitattributes'
run 'git config diff.ssenc.textconv "\"$SSENC\" decrypt --password-file \"$PASSWORD_FILE\" -i"'
run 'git --no-pager diff -- settings.yml.enc'
check "the plain-text diff shows the edited line" 'git --no-pager diff -- settings.yml.enc | grep -q "^+timeout: 60"'

echo "${0}: The history is readable the same way"
run 'git add .gitattributes settings.yml.enc && git commit -q -m "longer timeout"'
run 'git --no-pager log --oneline -p -1 -- settings.yml.enc'

echo "${0}: After a fresh checkout: decrypt to get the plain file back"
run 'rm settings.yml'
run '"$SSENC" decrypt --password-file "$PASSWORD_FILE" -i settings.yml.enc -o settings.yml'
run 'cat settings.yml'
run 'git status --short && echo "(clean: the plain file is ignored)"'
