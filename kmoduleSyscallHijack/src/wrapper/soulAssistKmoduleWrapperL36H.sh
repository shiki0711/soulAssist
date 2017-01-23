#!/system/bin/sh

THIS_FILE=$0

usage(){
    echo "Usage: $0 [-l|-u|-s|-f|-t] [option_value]";
    echo "    -l : load syscall hijack module";
    echo "    -u : unload syscall hijack module";
    echo "    -s : start hijack";
    echo "    -f : stop hijack";
    echo "    -l seconds: specify dungeon clrtime";
    exit 1;
}

noproc_exit(){
    echo "Soulseeker process not running! abort.";
    exit 1;
}

PROCESS_NAME="com.com2us.soulcollector.normal.freefull.google.global.android.common"

if [ -z "$1" ]; then
    usage
fi

while getopts "lusft:" arg
do
    case $arg in
        t)
          echo "$optarg" > /proc/soulseeker_hook/dungeon_clrtime
          ;;
        l)
          insmod hook.ko
          ;;
        u)
          rmmod hook
          ;;
        s)
          TGIDS=`ps | grep ${PROCESS_NAME} | awk '{print $2}' `;
          for TGID in $TGIDS; do
              if [ -d /proc/${TGID} ]; then
                  echo ${TGID} > /proc/soulseeker_hook/target_pid
                  break
              fi
          done
          if [ -z "${TGID}" ]; then
              noproc_exit
          fi
          ;;
        f)
          echo 0 > /proc/soulseeker_hook/target_pid  
          ;;
        ?)
          usage
          ;;
    esac
done


