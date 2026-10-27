db.items.mapReduce(function() { emit(this.kind,1); }, function(k,v) { return Array.sum(v); });
