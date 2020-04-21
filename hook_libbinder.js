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

const PYMODE = false;
var CACHE_LOG = "";

function log(type, message){
	if(message.ToString() == CACHE_LOG.toString()) return; //prevent duplication logs

	CACHE_LOG = message;
	if(PYMODE){
		send({'type':type, 'message': message});
	}
	else{
		console.log('[' + type + '] ' + message);
	}
}



// http://androidxref.com/kernel_3.10/xref/include/uapi/linux/android/binder.h
// enum_binder_driver_command_protocol
var binder_driver_command_protocol = {
	"BC_TRANSACTION": 0,
	"BC_REPLY": 1,
	"BC_ACQUIRE_RESULT": 2,
	"BC_FREE_BUFFER": 3,
	"BC_INCREFS": 4,
	"BC_ACQUIRE": 5,
	"BC_RELEASE": 6,
	"BC_DECREFS" :7,
    	"BC_INCREFS_DONE": 8,
    	"BC_ACQUIRE_DONE": 9,
   	 "BC_ATTEMPT_ACQUIRE": 10,
    	"BC_REGISTER_LOOPER": 11,
    	"BC_ENTER_LOOPER": 12,
    	"BC_EXIT_LOOPER": 13,
    	"BC_REQUEST_DEATH_NOTIFICATION": 14,
    	"BC_CLEAR_DEATH_NOTIFICATION": 15,
    	"BC_DEAD_BINDER_DONE": 16,

};
function parse_binder_transaction_data(binder_transaction_data){
	return {
        	"target": { // can either be u32 (handle) or 64b ptr
            		"handle": binder_transaction_data.readU32(),
            		"ptr": binder_transaction_data.readPointer()
        	},
        	"cookie": binder_transaction_data.add(8).readPointer(),
        	"code": binder_transaction_data.add(16).readU32(),
        	"flags": binder_transaction_data.add(20).readU32(),
        	"sender_pid": binder_transaction_data.add(24).readS32(),
        	"sender_euid": binder_transaction_data.add(28).readU32(),
        	"data_size": binder_transaction_data.add(32).readU64(),
        	"offsets_size": binder_transaction_data.add(40).readU64(),
        	"data": {
            	"ptr": {
                	"buffer": binder_transaction_data.add(48).readPointer(),
                	"offsets": binder_transaction_data.add(56).readPointer()
            	},
            	"buf": binder_transaction_data.add(48).readByteArray(8)
        }
    }
}


function handle_write(write_buffer, write_size, write_comsuned){
	var cmd = write_buffer.readU32() & 0xff;
	var ptr = write_buffer.add(write_consumed +4);
	var end = write_buffer.add(write_size);

	switch (cmd) {
		case binder_driver_command_protocol.BC_TRANSACTION:
		case binder_driver_command_protocol.BC_REPLY:
			var binder_transaction_data = parse_binder_transaction_data(ptr);

			//show me secrets
			log("INFO", "\n" + 
				hexdump(binder_transaction_data.data.ptr.buffer, {
					length: binder_transaction_data.data_size,
					ansi: true,}) + "\n");
			break;
		default:
	}


}



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

			if(binder_write_read.write_size > 0){
				//not yet!!!!!!!!!!!!!!!!!!!
				handle_write(binder_write_read.write_buffer, binder_write_read.write_size, binder_write_read.write_consumed);
			}
		}
	})


});
