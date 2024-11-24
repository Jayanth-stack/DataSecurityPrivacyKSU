import os


def setup_templates():
    """Create template directory structure and files"""
    # Create templates directory
    template_dir = 'templates'
    os.makedirs(template_dir, exist_ok=True)

    # Template definitions
    templates = {
        '404.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 h-screen flex items-center justify-center">
    <div class="text-center">
        <h1 class="text-6xl font-bold text-gray-800 mb-4">404</h1>
        <p class="text-xl text-gray-600 mb-8">Page not found</p>
        <a href="{{ url_for('login') }}" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
            Return to Login
        </a>
    </div>
</body>
</html>
''',

        '500.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>500 - Server Error</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
</head>
<body class="bg-gray-100 h-screen flex items-center justify-center">
    <div class="text-center">
        <h1 class="text-6xl font-bold text-gray-800 mb-4">500</h1>
        <p class="text-xl text-gray-600 mb-8">Internal Server Error</p>
        <a href="{{ url_for('login') }}" class="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded">
            Return to Login
        </a>
    </div>
</body>
</html>
''',

        'login.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Healthcare System - Login</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">
</head>
<body class="bg-gradient-to-r from-blue-100 to-blue-200 min-h-screen">
    <div class="min-h-screen flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
        <div class="max-w-md w-full space-y-8 bg-white p-8 rounded-xl shadow-lg">
            <div>
                <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">Healthcare System</h2>
                <p class="mt-2 text-center text-sm text-gray-600">Please sign in to access your account</p>
            </div>

            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="rounded-md p-4 {% if category == 'error' %}bg-red-50 text-red-700 border border-red-200{% else %}bg-green-50 text-green-700 border border-green-200{% endif %}">
                            <div class="flex">
                                <div class="flex-shrink-0">
                                    {% if category == 'error' %}
                                        <i class="fas fa-exclamation-circle"></i>
                                    {% else %}
                                        <i class="fas fa-check-circle"></i>
                                    {% endif %}
                                </div>
                                <div class="ml-3">
                                    <p class="text-sm font-medium">{{ message }}</p>
                                </div>
                            </div>
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            <form class="mt-8 space-y-6" action="{{ url_for('login') }}" method="POST">
                <div>
                    <label for="username" class="block text-sm font-medium text-gray-700">Username</label>
                    <input id="username" name="username" type="text" required 
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>

                <div>
                    <label for="password" class="block text-sm font-medium text-gray-700">Password</label>
                    <input id="password" name="password" type="password" required 
                           class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-blue-500 focus:border-blue-500">
                </div>

                <div>
                    <button type="submit" 
                            class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                        Sign in
                    </button>
                </div>
            </form>

            <!-- Test Credentials -->
            <div class="mt-6 border-t border-gray-200 pt-6">
                <div class="text-sm text-gray-600 text-center mb-4">Test Credentials</div>
                <div class="grid grid-cols-2 gap-4">
                    <div class="bg-gray-50 p-3 rounded">
                        <p class="font-semibold">Admin</p>
                        <p class="text-sm">Username: admin</p>
                        <p class="text-sm">Password: Admin@123456</p>
                    </div>
                    <div class="bg-gray-50 p-3 rounded">
                        <p class="font-semibold">Regular User</p>
                        <p class="text-sm">Username: regular_user</p>
                        <p class="text-sm">Password: Regular@123456</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
''',

        'dashboard.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Healthcare Dashboard</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/umd/react.production.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/react-dom/18.2.0/umd/react-dom.production.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/babel-standalone/7.22.20/babel.min.js"></script>
</head>
<body>
    <div id="root"></div>

    <script type="text/babel">
        const HealthcareDashboard = () => {
            const [records, setRecords] = React.useState([]);
            const [loading, setLoading] = React.useState(true);
            const [error, setError] = React.useState(null);
            const userGroup = "{{ user_group }}";

            React.useEffect(() => {
                fetchRecords();
            }, []);

            const fetchRecords = async () => {
                try {
                    const response = await fetch('/dashboard/data');
                    const data = await response.json();

                    if (data.error) {
                        throw new Error(data.error);
                    }

                    setRecords(data.records || []);
                } catch (err) {
                    setError(err.message);
                } finally {
                    setLoading(false);
                }
            };

            if (loading) {
                return <div>Loading...</div>;
            }

            if (error) {
                return <div className="text-red-600">{error}</div>;
            }

            return (
                <div className="min-h-screen bg-gray-100">
                    <nav className="bg-blue-600 text-white p-4">
                        <div className="container mx-auto flex justify-between items-center">
                            <h1 className="text-xl font-bold">Healthcare Dashboard</h1>
                            <div className="flex items-center space-x-4">
                                <span>Welcome, {{ username }}</span>
                                <a href="/logout" className="bg-blue-700 px-4 py-2 rounded hover:bg-blue-800">
                                    Logout
                                </a>
                            </div>
                        </div>
                    </nav>

                    <main className="container mx-auto p-6">
                        <div className="bg-white rounded-lg shadow-lg p-6">
                            <table className="min-w-full divide-y divide-gray-200">
                                <thead className="bg-gray-50">
                                    <tr>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">ID</th>
                                        {userGroup === "H" && (
                                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                                        )}
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Age</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Gender</th>
                                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {records.map((record) => (
                                        <tr key={record.id}>
                                            <td className="px-6 py-4">{record.id}</td>
                                            {userGroup === "H" && (
                                                <td className="px-6 py-4">{record.first_name} {record.last_name}</td>
                                            )}
                                            <td className="px-6 py-4">{record.age}</td>
                                            <td className="px-6 py-4">{record.gender}</td>
                                            <td className="px-6 py-4">
                                                <a href={`/view-record/${record.id}`} className="text-blue-600 hover:text-blue-900">View</a>
                                            </td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </main>
                </div>
            );
        };

        ReactDOM.render(<HealthcareDashboard />, document.getElementById('root'));
    </script>
</body>
</html>
'''
    }

    # Create each template file
    for template_name, template_content in templates.items():
        template_path = os.path.join(template_dir, template_name)
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(template_content.strip())
        print(f"Created template: {template_name}")


if __name__ == "__main__":
    setup_templates()