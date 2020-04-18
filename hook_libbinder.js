/**
 * frida -U -q -n com.google.android.keep -e "Process.enumerateModules();
 * 결과
 * {
 *	base :0x70d29b7000
 *	name : libbinder.so
 *	path : /system/lib64/libbinder.so
 *	size :507904
 *
 * }
 */



Java.perform(function(){
	
	// ioctl 시스템콜을 후킹 포인트로 선정, 커널과 가장 가까운 단계에서 바인더 메시지를 보내는데 사용되는 시스템콜
	var ioctl = Module.findExportByName("libbinder.so", "ioctl");
	Interceptor.attach(ioctl, {
		onEnter: function(args){
			// args[0] :파일 디스크립터
			// args[1] : 명령을 나타내는 정수
			// args[2] : 특정 구조체를 가리키는 포인터
			var fd = args[0];
			var cmd = args[1];
			
			if(cmd != 0xc0306201) return; // example은 0xc0306201 주소가 BINDER_WRITE_READ인데, 내 기기에 맞게 포팅해야함.
			var data = args[2]; // binder_write_read에 대한 포인터
		}
	})


});
