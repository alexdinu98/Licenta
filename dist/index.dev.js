"use strict";

var express = require('express');

var app = express();

var routes = require('./controllers/routes');

var path = require('path');

var methodOverride = require('method-override');

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(methodOverride('_method'));
app.get('/', routes);
app.post('/register', routes);
app.get('/login', routes);
app.post('/login', routes);
app.get('/success', routes);
app.get('/logout', routes);
app.get('/files', routes);
app.post('/upload', routes);
app.get('/files', routes);
app.get('/files/:filename', routes);
app.get('/stl/:filename', routes);
app["delete"]('/files/:id', routes);
var PORT = process.env.PORT || 8000;
app.listen(PORT, function () {
  return console.log("Server Stated At Port", PORT);
});