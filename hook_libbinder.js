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


// // http://androidxref.com/kernel_3.18/xref/drivers/staging/android/uapi/binder.h#77 ==> blog에 나온 주소
// http://androidxref.com/kernel_3.10/xref/include/uapi/linux/android/binder.h ==> 기기에 맞는 커널 버전
function parse_struct_binder_write_read(binder_write_read){
	var offset = 8; //64b

	return{
		"write_size": binder_write_read.readU64(),
		"write_consumed": binder_write_read.add(offset).readU64(),
		"write_buffer": binder_write_read.add(offset*2).readPointer(),
		"read_size": binder_write_read.add(offset*3).readU64(),
		"read.consumed": binder_write_read.add(offset*4).readU64(),
		"read_buffer": binder_write_read.add(offset*5).readPointer()


	}

}



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
			//https://android.googlesource.com/platform/system/sepolicy/+/master/public/ioctl_defines
			//해당 주소를 참조하면, 0xc0306201이 BINDER_WRITE_READ로 정의됨을 확인 할 수 있음.
			//추가적으로 binder_debug 파일에 과정을 수행 시 0xc0306201 주소가 나오며... 어느정도 유추는 가능

			var data = args[2]; // binder_write_read에 대한 포인터
			var binder_write_read = parse_struct_binder_write_read(data);
		}
	})


});
