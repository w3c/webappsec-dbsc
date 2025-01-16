# TODO 🚧

Your new site is all yours so it doesn't matter if you break it! Try editing the code.

Let's keep track of the submitted favorites using an array. First add this code near the top of `server.js` (where the comment says `ADD FAVORITES ARRAY VARIABLE`):

```js
const favorites = [];
```

In the `POST` route, inside the `if(color)` block, add this code to save the submitted value to the array, and write it to the console:

```js
favorites.push(color);
console.log(favorites);
```

Click __Tools__ > __Logs__ at the bottom of Glitch to see the log statement in action when you submit new colors through the form.

## Keep going! 🚀

Clearly this is not a robust data storage approach and won't persist for long! Your Node apps can use a variety of databases, like [SQLite](https://glitch.com/~glitch-hello-sqlite) and [Airtable](https://glitch.com/~glitch-hello-airtable).
