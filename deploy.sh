set -e

# Usage:
#   ./deploy.sh <remote name> <branch name>
# Pushes the current state of <branch name> to the Glitch remote <remote
# name>. <branch name> defaults to "origin/glitch", and <remote name> to
# "glitch".

# One time setup:

# This requires you to have setup an upstream which points to
# the URL fetched from the Glitch UI (Tools -> Import / Export).
# You can create the upstream with:
#   git remote add <remote name> $GLITCH_URL
#   git fetch <remote name>
# It is recommended to have one upstream called "glitch" for the
# prototype server, https://glitch.com/edit/#!/dbsc-prototype-server,
# and one for a personal remix of that project you can use for staging.

# Recommended Development process:

# Create a new branch tracking the main repo:
#   git new-branch --upstream origin/glitch <branch name>
# Develop your code on that branch
# Test with:
#   ./deploy.sh <personal remix> <branch name>
# When satisfied, push this branch and create a pull request:
#   git push -u origin <branch name>
# When the pull request is landed, deploy to the prototype server:
#   ./deploy.sh

BRANCH=${2:-origin/glitch}
REMOTE=${1:-glitch}

git new-branch --upstream $REMOTE/main deploy_glitch
git checkout $BRANCH -- .
git commit -a -m "Automated deployment"
git push -u $REMOTE deploy_glitch:main
git checkout $BRANCH
git branch -D deploy_glitch
