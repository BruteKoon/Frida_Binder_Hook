


Java.perform(function(){
	
	// ioctl 시스템콜을 후킹 포인트로 선정, 커널과 가장 가까운 단계에서 바인더 메시지를 보내는데 사용되는 시스템콜
	var ioctl = Moudle.findExportByName("libbinder.so", "ioctl");
	Interceptor.attach(ioctl, {
		console.log("ioctl hook");
		
		onEnter: function(args){
			// args[0] :파일 디스크립터
			// args[1] : 명령을 나타내는 정수
			// args[2] : 특정 구조체를 가리키는 포인터
			var fd = args[0];
			var cmd = args[1];
			console.log(args);
		}
	})


});
