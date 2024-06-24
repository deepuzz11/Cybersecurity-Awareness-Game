$(document).ready(function() {
    $('#content').html(`
        <form id="registerForm">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" class="form-control" id="username" required>
            </div>
            <button type="submit" class="btn btn-primary">Register</button>
        </form>
    `);

    $('#registerForm').submit(function(e) {
        e.preventDefault();
        const username = $('#username').val();
        $.post('/register', { username: username }, function(data) {
            localStorage.setItem('user_id', data.user_id);
            loadQuests();
        });
    });

    function loadQuests() {
        $.get('/quests', function(data) {
            let questsHtml = '<h2>Available Quests</h2><ul class="list-group">';
            data.forEach(quest => {
                questsHtml += `
                    <li class="list-group-item">
                        <h3>${quest.title}</h3>
                        <p>${quest.description}</p>
                        <button class="btn btn-success complete-quest" data-id="${quest.id}">Complete Quest</button>
                    </li>
                `;
            });
            questsHtml += '</ul>';
            $('#content').html(questsHtml);
        });
    }

    $(document).on('click', '.complete-quest', function() {
        const questId = $(this).data('id');
        const userId = localStorage.getItem('user_id');
        $.post('/complete_quest', { user_id: userId, quest_id: questId }, function(data) {
            alert('Quest completed!');
            loadLeaderboard();
        });
    });

    function loadLeaderboard() {
        $.get('/leaderboard', function(data) {
            let leaderboardHtml = '<h2>Leaderboard</h2><ul class="list-group">';
            data.forEach(user => {
                leaderboardHtml += `
                    <li class="list-group-item">
                        ${user.username} - ${user.points} points
                    </li>
                `;
            });
            leaderboardHtml += '</ul>';
            $('#content').html(leaderboardHtml);
        });
    }
});
