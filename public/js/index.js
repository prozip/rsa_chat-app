const socket = io();
const rsa = forge.pki.rsa;

var userlist = []
var id = -1
var keyPair = null
var msgList = []
var sendCountList = []
var receiveCountList = []
var groupMsgList = []

var name = prompt('Bạn tên gì?')
document.querySelector('#name').innerText = name
document.getElementById("welcomeName").innerText = name

const form = document.querySelector('#form')
const input = document.querySelector('#input')
const publicKeyListNode = document.getElementById("publicKeyList")
const userlistNode = document.getElementById("userOption")
const msgListNode = document.getElementById("yourMsg")

generateKeyPair()

function generateKeyPair() {
    rsa.generateKeyPair({ bits: 4096, workers: -1 }, function (err, keypair) {
        keyPair = keypair
        socket.emit('sendPublicKey', {
            name: name,
            publicKey: forge.pki.publicKeyToPem(keypair.publicKey)
        })
    });
}

function increaseCount(index) {
    if (sendCountList[index]) {
        sendCountList[index] += 1
    } else {
        sendCountList[index] = 1
    }
}

// send msg
form.addEventListener('submit', (e) => {
    e.preventDefault()
    if (input.value) {
        // send msg to group
        if (userlistNode.value == 'all') {
            socket.emit('groupChat', {
                id,
                msg: input.value
            })
        } else {
            // send private msg
            var receiveID = userlistNode.value
            msgList.push({
                id: receiveID + '%',
                msg: input.value
            })

            increaseCount(receiveID)


            // =================================================================
            // encrypt msg #text1=({msg+CA}pubB)
            let pem = userlist[receiveID].publicKey
            let publicKey = forge.pki.publicKeyFromPem(pem)
            let msg = {
                msg: input.value,
                count: sendCountList[receiveID]
            }
            let encryptMsg = publicKey.encrypt(forge.util.encodeUtf8(JSON.stringify(msg)))


            // hash encryted msg #text2=hash(text1)
            let md = forge.md.sha256.create();
            md.update(encryptMsg);


            // sign hashed encrtyed msg #text3=(text2)privA
            let signedMsg = keyPair.privateKey.sign(md)

            // =================================================================


            socket.emit('privateChat', {
                id,
                encryptMsg, // #text1
                receiveID,
                signedMsg, // #text3
            })
            console.log(sendCountList[receiveID])
        }
        input.value = ''
        refreshChat()
    }
})


// received private msg
socket.on("privateMsgFromServer", (data) => {


    let pem = userlist[data.sendID].publicKey
    let publicKey = forge.pki.publicKeyFromPem(pem)

    // hash receive msg #Text4=hash(text1)
    let md = forge.md.sha256.create();
    md.update(data.encryptMsg)
    let hashedMsg = md.digest().bytes();

    try {
        // check sign key
        // #text4 ? #Text5=pubA(text3) 
        if (publicKey.verify(hashedMsg, data.signedMsg)) {
            // valid, decrypt hashed msg
            // #Text6=privB(text1)

            let receiveObj = keyPair.privateKey.decrypt(data.encryptMsg)
            let {msg, count} = JSON.parse(receiveObj) 
            let sendID = data.sendID

            console.log(msg, count)

            // check count
            if (!receiveCountList[sendID] | receiveCountList[sendID] < count) {
                
                if (receiveCountList[sendID] + 1 < count) {
                    alert(`thiếu  ${count - receiveCountList[sendID] -1 } tin nhắn`)
                }

                // update count
                receiveCountList[sendID] = count

                // add to interface
                msgList.push({
                    id: sendID,
                    msg: msg
                })
                refreshChat()
            } else {
                console.log(sendID)
                alert("count ko hợp lệ")
            }

        } else {
            console.log(data.sendID)
            alert("tin nhắn ko hợp lệ")
        }
    } catch (error) {
        alert(error)
    }
})

// received msg from group
socket.on('groupChatFromServer', (data) => {
    groupMsgList.push({
        id: data.id,
        msg: data.msg
    })
    refreshChat()
})


// update chat msg
function refreshChat() {
    msgListNode.innerHTML = ""
    let chatType = document.getElementById("ChatType")
    if (userlistNode.value == "all") {
        chatType.innerHTML = "THIS ROOM IS UNSECURE"
        groupMsgList.forEach(data => {
            let li = document.createElement('li')
            if (data.id == id) {
                li.textContent = `you : ${data.msg}`
            } else {
                li.textContent = `${userlist[data.id].name} #${data.id} : ${data.msg}`
            }
            msgListNode.appendChild(li)
        })
    } else {
        chatType.innerHTML = "This room is safe"
        msgList.forEach(data => {
            if (data.id == userlistNode.value | data.id == userlistNode.value + "%") {
                let li = document.createElement('li')

                if (data.id == userlistNode.value + "%") {
                    li.textContent = `you : ${data.msg}`
                } else {
                    li.textContent = `${userlist[data.id].name} #${data.id} : ${data.msg}`
                }
                msgListNode.appendChild(li)
            }
        });
    }
}


// received publicKey
socket.on('getPublicKey', (userList) => {
    console.log(userList)
    userlist = userList
    publicKeyListNode.innerHTML = ""
    userlistNode.innerHTML = ""

    if (id == -1) {
        id = userList.length - 1
        document.querySelector('#name').innerText = `${name} #${id}`
        document.getElementById("welcomeName").innerText = `Chào mừng, ${name} #${id}` 
    }

    // group chat option
    const opt = document.createElement('option')
    opt.value = "all"
    opt.textContent = "all"
    userlistNode.appendChild(opt)

    // update user option
    for (let i = 0; i < userList.length; i++) {
        let user = userList[i]
        if (i != id) {
            const li = document.createElement('li')
            li.textContent = `${user.name} #${i}`
            publicKeyListNode.appendChild(li)

            const opt = document.createElement('option')
            opt.value = i
            opt.textContent = `${user.name} #${i}`
            userlistNode.appendChild(opt)
        }
    }
})