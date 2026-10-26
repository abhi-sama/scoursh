const target = Object.create(null); Reflect.setPrototypeOf(target, {}); target.__proto__ = req.body;
