set -e

# Usage:
#   ./deploy.sh <branch to deploy>
# The branch is optional and defaults to origin/glitch.
#
# This requires you to have an upstream called "glitch" which points to
# the URL fetched from the Glitch UI. You can create one with:
#   git remote add glitch $GLITCH_URL

git new-branch --upstream glitch/main deploy_glitch
git checkout ${1:-origin/glitch} -- .
git commit -a -m "Automated deployment"
git push -u glitch deploy_glitch:main
git checkout ${1:-origin/glitch}
git branch -D deploy_glitch
