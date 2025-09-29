document.addEventListener('DOMContentLoaded', () => {
    const chatContainer = document.getElementById('chatContainer');
    const messageInput = document.getElementById('messageInput');
    const sendButton = document.getElementById('sendButton');
    const voiceButton = document.getElementById('voiceButton');
    const uploadForm = document.getElementById('uploadForm');
    const fileInput = document.getElementById('fileInput');
    const historyButton = document.getElementById('historyButton');

    let chatHistory = [];
    let currentConversationId = null;
    let isHistoryMode = false;

    // History dropdown
    const conversationDropdown = document.createElement('div');
    conversationDropdown.className = 'dropdown';
    document.body.appendChild(conversationDropdown);

    const addMessageToUI = (content, role = 'ai', isHtml = false) => {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${role === 'user' ? 'user' : 'ai'}`;

        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';
        contentDiv.innerHTML = isHtml ? content : (role === 'ai' ? `<p style="margin:8px 0; line-height:1.5;">${content}</p>` : content);

        messageDiv.appendChild(contentDiv);
        chatContainer.appendChild(messageDiv);
        chatContainer.scrollTop = chatContainer.scrollHeight;
    };

    const formatFileAnalysis = (res) => {
        const filename = res.file.includes('/') ? res.file.split('/').pop() : res.file;
        const findings = res.findings && res.findings.length
            ? `<details open>
                <summary>Findings (${res.findings.length})</summary>
                <pre>${JSON.stringify(res.findings, null, 2)}</pre>
               </details>`
            : `<div style="margin:2px 0; font-size:0.85em; color:#888;">No obvious issues found.</div>`;
        return `
                <div class="file-result">
                <div class="file-header">${filename}
                Lines: ${res.line_count}, 
                Language: ${res.language}, 
                Size: ${res.file_size} bytes</div>
                ${findings}
            </div>`;
    };

    const showTypingIndicator = () => {
        removeTypingIndicator();
        const typingDiv = document.createElement('div');
        typingDiv.className = 'message ai';
        typingDiv.id = 'typingIndicator';
        typingDiv.innerHTML = `<div class="typing-indicator show"><span></span><span></span><span></span></div>`;
        chatContainer.appendChild(typingDiv);
        chatContainer.scrollTop = chatContainer.scrollHeight;
    };

    const removeTypingIndicator = () => {
        const indicator = document.getElementById('typingIndicator');
        if (indicator) indicator.remove();
    };

    const saveConversationToLocalStorage = () => {
        if (!chatHistory.length) return;
        const conversations = JSON.parse(localStorage.getItem('conversations')) || [];
        if (!currentConversationId) {
            currentConversationId = Date.now().toString();
            const title = chatHistory.find(m => m.role==='user')?.content.slice(0,50)+'...' || 'New Conversation';
            conversations.push({id: currentConversationId, title, date: new Date().toLocaleString(), messages: chatHistory});
        } else {
            const idx = conversations.findIndex(c => c.id===currentConversationId);
            if (idx!==-1) conversations[idx].messages = chatHistory;
        }
        localStorage.setItem('conversations', JSON.stringify(conversations));
    };

    const loadConversation = (id) => {
        const conversations = JSON.parse(localStorage.getItem('conversations')) || [];
        const conv = conversations.find(c=>c.id===id);
        if (!conv) return;
        chatContainer.innerHTML = '';
        conv.messages.forEach(m=>addMessageToUI(m.content, m.role, m.isHtml));
        chatHistory = conv.messages;
        currentConversationId = conv.id;
    };

    const showHistory = () => {
        const conversations = JSON.parse(localStorage.getItem('conversations')) || [];
        conversationDropdown.innerHTML = '';
        conversations.forEach(conv => {
            const item = document.createElement('div');
            item.className = 'dropdown-item';
            item.innerHTML = `<strong>${conv.title}</strong> — <span>${conv.date}</span>`;
            item.onclick = ()=>{ loadConversation(conv.id); toggleHistoryMode(false); };
            conversationDropdown.appendChild(item);
        });
    };

    const toggleHistoryMode = (forceState) => {
        isHistoryMode = (typeof forceState==='boolean')?forceState:!isHistoryMode;
        if (isHistoryMode) {
            showHistory();
            conversationDropdown.classList.add('show');
            historyButton.innerHTML = '📜 ▼';
            const rect = historyButton.getBoundingClientRect();
            conversationDropdown.style.top = `${rect.bottom+4}px`;
            conversationDropdown.style.left = `${rect.left}px`;
        } else {
            conversationDropdown.classList.remove('show');
            historyButton.innerHTML = '📜';
        }
    };

    const sendMessage = async () => {
        const text = messageInput.value.trim();
        if (!text) return;
        addMessageToUI(text, 'user');
        chatHistory.push({role:'user', content:text});
        messageInput.value=''; sendButton.disabled=true; showTypingIndicator();

        try {
            const res = await fetch('/chat', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({message:text})});
            const data = await res.json();
            removeTypingIndicator();
            addMessageToUI(data.response, 'assistant');
            chatHistory.push({role:'assistant', content:data.response});
            saveConversationToLocalStorage();
        } catch(e){ console.error(e); removeTypingIndicator(); addMessageToUI("Sorry, there was an error.",'assistant'); }
        finally { sendButton.disabled=false; messageInput.focus(); }
    };

    uploadForm.addEventListener('submit', async e=>{
        e.preventDefault();
        const files = fileInput.files;
        if(!files.length) return alert("Select files or a folder first.");
        addMessageToUI(`📂 Uploading ${files.length} file(s)...`,'user');
        chatHistory.push({role:'user', content:`Uploaded ${files.length} files`});

        const formData = new FormData();
        Array.from(files).forEach(f=>formData.append('files',f));
        showTypingIndicator();

        try {
            const res = await fetch('/upload',{method:'POST',body:formData});
            const data = await res.json();
            removeTypingIndicator();
            data.results.forEach(r=>{
                const html = formatFileAnalysis(r);
                addMessageToUI(html,'assistant',true);
                chatHistory.push({role:'assistant',content:html,isHtml:true});
            });
            saveConversationToLocalStorage();
        } catch(err){ console.error(err); removeTypingIndicator(); addMessageToUI("Upload failed.",'assistant'); }
    });

    sendButton.addEventListener('click', sendMessage);
    messageInput.addEventListener('keypress', e=>{if(e.key==='Enter'&&!sendButton.disabled) sendMessage();});
    voiceButton.addEventListener('click',()=>alert('Voice feature coming soon! 🎤'));
    historyButton.addEventListener('click',()=>toggleHistoryMode());
    document.addEventListener('click', e=>{
        if(isHistoryMode && !historyButton.contains(e.target) && !conversationDropdown.contains(e.target)) toggleHistoryMode(false);
    });

    addMessageToUI("Hello! I'm your AI assistant. How can I help you today?");
});
