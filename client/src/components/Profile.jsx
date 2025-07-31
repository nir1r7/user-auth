import React, { useState, useEffect } from 'react';

function Profile() {
    const [user, setUser] = useState({});
    const [message, setMessage] = useState('');

    useEffect(() => {
        const fetchProfile = async () => {
            const token = localStorage.getItem('token');
            if (!token) {
                setMessage('No token found, please log in.');
                return;
            }

            try {
                const response = await fetch('http://localhost:5000/profile', {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${token}`,
                    },
                });

                if (response.ok) {
                    const data = await response.json();
                    setUser(data.user);
                } else {
                    const errorData = await response.json();
                    setMessage(`Error fetching profile: ${errorData.error}`);
                }
            } catch (error) {
                setMessage(`Error: ${error.message}`);
            }
        }
        fetchProfile();
    }, []);

    return (
        <div>
            <h2>User Profile</h2>
            <div>
                <p>Email: {user.email}</p>
                <p>Role: {user.role}</p>
                <p>{message}</p>
            </div>
        </div>
  );
}

export default Profile;