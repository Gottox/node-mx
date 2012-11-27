var bcrypt = require('bcrypt');


function extend(opt) {
	for(var i = 1; i < arguments.length; i++)
		for(var k in arguments[i])
			opt[k] = arguments[i][k];
		return opt;
}

module.exports = exports = function mx(schema, opts) {
	var options = extend({
		salt: 10
	}, opts);

	if(!('name' in schema.tree || 'password' in schema.tree))
		throw "Your Model must contain name and password";

	schema.add({
		loginAt: Date
	})
	
	schema.virtual('isRegistered')
	.get(function() {
		return !this.isNew;
	})

	schema
	
	.static('mx', function() {
		return new MX(this, options)
	})

	.static('findByNameAndPassword', function(name, password, cb) {
		this.findOne({name: name}, function(err, obj) {
			if(err || !obj) return cb.apply(obj, arguments);

			bcrypt.compare(password, obj.password, function(err, isMatch) {
				arguments[1] = isMatch ? obj : null;
				return cb.apply(obj, arguments);
			});
		});
	})

	.pre('save', function() {
		var self = this;
		if (!self.isModified('password')) return next();
		bcrypt.genSalt(options.salt, function(err, salt) {
			if (err) return next(err);

			bcrypt.hash(self.password, salt, function(err, hash) {
				if (err) return next(err);

				self.password = hash;
				next();
			});
		});
	})
}

function MX(Model, options) {
	this.Model = Model;
	this.options = options;
	this.accessor = Model.modelName.toLowerCase();

	for(var k in {load:1, login:1, logout:1}) {
		this[k] = this[k].bind(this);
	}
}
MX.prototype = {
	_pubObj: function(req, obj) {
		var accessor = this.accessor;
		var oldAccessor = 'old' + accessor[0].toUpperCase() + accessor.substr(1);
		if(!req.mx)
			req.mx = {};

		if(!obj) {
			obj = req.mx[accessor];
			if(!obj)
				obj = new this.Model();
		}
		if(obj instanceof this.Model == false) {
			obj = new this.Model(obj);
		}
	
		if(req.mx[accessor] && String(obj._id) != String(req.mx[accessor]._id))
			req.mx[oldAccessor] = req.mx[accessor];
		req.session['_'+accessor] = (req.mx[accessor] = obj).toObject({virtuals:true});
	},

	login: function(req, res, next) {
		var self = this;
		var name = req.body.name;
		var password = req.body.password;

		if(!name && !password)
			return next();

		this.Model.findByNameAndPassword(name, password, function(err, obj) {
			if(err) return next(err);
			if(obj) {
				obj.loginAt = Date.now();
			}
			req.mxLogin = !!obj;
			self._pubObj(req, obj);
			next();
		})
	},

	logout: function(req, res, next) {
		var accessor = this.accessor;
		req.mxLogout = false;
		if(req.mx && req.mx[accessor] && req.mx[accessor].isRegistered) {
			this._pubObj(req, new this.Model());
			req.mxLogout = true;
		}
		next();
	},

	load: function(req, res, next) {
		var self = this;
		var accessor = this.accessor;

		this._loadObj(req.session, function(err, obj) {
			if(err) return next(err);
			self._pubObj(req, obj)
			next();
		})
	},

	_loadObj: function(session, cb) {
		var accessor = this.accessor;
		var obj = session['_'+accessor];
		if(!session['_'+accessor] || !session['_'+accessor].isRegistered)
			return cb(null, obj);

		this.Model.findOne(obj._id, function(err, dbObj) {
			if(err) return cb(err);

			return cb(null, dbObj);
		})
	},

	socketio: function(cb) {
		var self = this;
		return function(err, socket, session) {
			if(err) return cb(err);
			self._loadObj(session, function(err, obj) {
				if(err) return cb(err);

				return cb(err, socket, session, obj);
			})
		}
	}
}
