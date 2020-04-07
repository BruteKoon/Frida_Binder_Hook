


Java.perform(function(){
	var ioctl = Moudle.findExportByName("libbinder.so", "ioctl");
	Interceptor.attach(ioctl, {
		console.log("ioctl hook");
	})


});
