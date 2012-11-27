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
		if('isRegistered' in this)
			this.isRegistered = true;
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
	_pubObj: function(req, obj, registered) {
		var accessor = this.accessor;
		var oldAccessor = 'old' + accessor[0].toUpperCase() + accessor.substr(1);
		if(req[accessor])
			req[oldAccessor] = 
				req[accessor];
		obj.isRegistered = !!registered;
		req.session[accessor] = req[accessor] = obj;
	},

	login: function(req, res, next) {
		var name = req.body.name;
		var password = req.body.password;

		if(!name && !password)
			return next();

		this.Model.findByNameAndPassword(name, password, function(err, obj) {
			if(err) return next(err);
			if(obj)
				obj.loginAt = Date.now();
			this._pubObj(req, obj || new (this.Model)(), !!obj);
			if(obj && this.Model.schema.methods.onLogin) {
				obj.onLogin(req, res, next);
			}
			else
				next();
		})
	},

	logout: function(req, res, next) {
		this.load(req, res, function() {
			this._pubObj(req, new this.Model(), false);
			next.apply(this, arguments);
		})
	},

	load: function(req, res, next) {
		var accessor = this.accessor;
		var obj = new this.Model(req.session[accessor]);
		if(req.session[accessor] && req.session[accessor].isRegistered) {
			this.Model.findOne(obj._id, function(err, dbObj) {
				if(err)
					return next(err);

				this._pubObj(req, dbObj || obj, dbObj);
				return next();
			})
		}
		else {
			this._pubObj(req, obj, false);
			return next();
		}
	}
}
