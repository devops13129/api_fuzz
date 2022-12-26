#! /bin/bash

cd /app
tox
rc=$?
if [[ $rc -ne 0 ]] ; then
    echo 'Testing of flask rest target failed'; ext $rc
fi

echo "FINISHED" > /output/peachweb-flasktarget.status
