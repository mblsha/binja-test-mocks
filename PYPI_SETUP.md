# PyPI Setup Guide for binja-test-mocks

## Step 1: Create PyPI Account
1. Go to https://pypi.org/account/register/
2. Create account and verify email
3. Enable 2FA (recommended)

## Step 2: Upload Package Manually (First Time)

### Test Upload to TestPyPI (Optional but Recommended)
```bash
# Upload to test PyPI first
python -m twine upload --repository testpypi dist/*

# When prompted:
# Username: __token__
# Password: (use your TestPyPI token or your password)
```

### Upload to Real PyPI
```bash
# Upload to PyPI
python -m twine upload dist/*

# When prompted:
# Username: __token__ 
# Password: (paste your API token starting with pypi-)
# OR
# Username: (your PyPI username)
# Password: (your PyPI password)
```

## Step 3: Configure Trusted Publishing

Once your package is uploaded, you can set up trusted publishing for automatic releases from GitHub Actions:

### 3.1 Go to Your Project Settings
1. Log in to https://pypi.org
2. Go to your project: https://pypi.org/manage/project/binja-test-mocks/
3. Click "Settings" in the left sidebar
4. Scroll to "Publishing" section

### 3.2 Add GitHub Publisher
Click "Add a new publisher" and fill in:

- **Owner**: `mblsha`
- **Repository name**: `binja-test-mocks`
- **Workflow name**: `publish.yml`
- **Environment name**: `pypi` (this matches our workflow)

### 3.3 Save the Configuration
Click "Add" to save the trusted publisher configuration.

## Step 4: Test Trusted Publishing

### 4.1 Update Version
Edit `src/binja_test_mocks/__init__.py`:
```python
__version__ = "0.1.1"  # Bump version
```

### 4.2 Commit and Tag
```bash
git add -A
git commit -m "Bump version to 0.1.1"
git tag v0.1.1
git push origin main --tags
```

### 4.3 Create GitHub Release
1. Go to https://github.com/mblsha/binja-test-mocks/releases
2. Click "Create a new release"
3. Choose tag `v0.1.1`
4. Set release title: "v0.1.1"
5. Add release notes
6. Click "Publish release"

The GitHub Action will automatically:
- Build the package
- Upload to PyPI using trusted publishing
- No API tokens needed!

## Trusted Publishing Benefits

1. **No secrets to manage**: No API tokens in GitHub
2. **More secure**: Uses OpenID Connect (OIDC)
3. **Audit trail**: All publishes linked to GitHub Actions
4. **Easy revocation**: Remove publisher from PyPI settings

## Troubleshooting

### "Invalid publisher" Error
- Check workflow filename matches exactly
- Verify environment name matches
- Ensure you're using the correct GitHub username/repo

### "Not authorized" Error
- Make sure you own the PyPI project
- Verify trusted publisher is configured
- Check GitHub Actions has `id-token: write` permission

### Build Issues
- Ensure version number is bumped
- Check `python -m build` works locally
- Verify all tests pass