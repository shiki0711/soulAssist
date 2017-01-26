#!/system/bin/sh

THIS_FILE=$0

usage(){
    echo "Usage: $0 [-l|-u|-s|-f|-d|-r|-t] [optional_value]";
    echo "    -l : load syscall hijack module";
    echo "    -u : unload syscall hijack module";
    echo "    -s : start hijack";
    echo "    -f : stop hijack";
    echo "    -r : win tower rush";
    echo "    -d : dump packet info to kmsg";
    echo "    -t seconds: specify dungeon clrtime";
    exit 1;
}

noproc_exit(){
    echo "Game not running! abort.";
    exit 1;
}

PROCESS_NAME="com.com2us.soulcollector.normal.freefull.google.global.android.common"

if [ -z "$1" ]; then
    usage
fi

while getopts "lusfrdt:" arg
do
    case $arg in
        r)
          echo 1 > /proc/soulseeker_hook/tower_rush_win
          ;;
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
        d)
          echo 1 > /proc/soulseeker_hook/debug_dump_packet
          ;;
        ?)
          usage
          ;;
    esac
done


