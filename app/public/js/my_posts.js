function getCookieValue(name) {
    const cookies = document.cookie ? document.cookie.split('; ') : [];

    for (const cookie of cookies) {
        const parts = cookie.split('=');
        if (parts[0] === name) {
            return decodeURIComponent(parts.slice(1).join('='));
        }
    }

    return '';
}

// Function to load posts made by user who is currently logged in
async function loadPosts() {

    // Load posts data
    const post_response = await fetch("/my-posts-data", { cache: 'no-store' });

    if (post_response.status === 401) {
        window.location.href = '/';
        return;
    }

    const post_data = await post_response.json();

    // Remove current posts
    let postList = document.getElementById('myPosts');

    for(let i = 0; i < postList.children.length; i++) {
        if(postList.children[i].nodeName == "article") {
            postList.removeChild(postList.children[i]);
        }
    }

    // Add posts made by current user
    for(let i = 0; i < post_data.length; i++) {
        let author = post_data[i].username;
        let timestamp = post_data[i].timestamp;
        let title = post_data[i].title;
        let content = post_data[i].content;
        let postId = post_data[i].postId;

        let postContainer = document.createElement('article');
        postContainer.classList.add("post");
        let fig = document.createElement('figure');
        postContainer.appendChild(fig);

        let postIdContainer = document.createElement("h6");
        postIdContainer.textContent = postId;
        postIdContainer.hidden = true;
        postId.id = "postId";
        postContainer.appendChild(postIdContainer);

        let figcap = document.createElement('figcaption');
        fig.appendChild(figcap);

        let titleContainer = document.createElement('h3');
        titleContainer.textContent = title;
        figcap.appendChild(titleContainer);

        let usernameContainer = document.createElement('h5');
        usernameContainer.textContent = author;
        figcap.appendChild(usernameContainer);

        let timeContainer = document.createElement('h5');
        timeContainer.textContent = timestamp;
        figcap.appendChild(timeContainer);

        let contentContainer = document.createElement('p');
        contentContainer.id = "content";
        contentContainer.textContent = content;
        figcap.appendChild(contentContainer);

        let editBtn = document.createElement('button');
        editBtn.classList.add('editBtn');
        editBtn.textContent = "Edit";
        editBtn.addEventListener("click", editPost);
        postContainer.appendChild(editBtn);

        let delBtn = document.createElement('button');
        delBtn.classList.add('delBtn');
        delBtn.textContent = "Delete";
        delBtn.addEventListener("click", deletePost);
        postContainer.appendChild(delBtn);

        postList.insertBefore(postContainer, document.querySelectorAll("article")[0]);
        appendPostImages(postId, figcap, true, contentContainer);
    }
}

loadPosts();

// Function to remove a post from the page after clicking delete - this is also reflected on the server side
function deletePost(e) {

    // Get the post that was clicked
    let post = e.target.parentNode;

    // Put post in object to be the body of fetch request
    const postData = {
        postId: post.getElementsByTagName('h6')[0].textContent,
    };

    const requestHeaders = {
        "Content-Type": "application/json",
        "X-CSRF-Token": getCookieValue('csrf_token')
    };

    // Delete post
  fetch('/deletepost', {
    method: 'POST',
    headers: requestHeaders,
    body:JSON.stringify(postData)
  });

  // Hide element on button click so deletion appears immediate
  e.target.parentNode.hidden = true;
}

// Function to edit post
function editPost(e) {

    // Get post that the user clicked on
    let post = e.target.parentNode;

    // Fill out form fields with data grabbed from post
    document.getElementById("title_field").value = post.getElementsByTagName('h3')[0].textContent;
    document.getElementById("content_field").value = post.getElementsByTagName('p')[0].textContent;
    document.getElementById("postId").value = post.getElementsByTagName('h6')[0].textContent;

    // Scroll user to post form
    document.getElementById("postForm").scrollIntoView({behavior: "smooth"});

}

// Function to filter posts on page using search bar
function searchPosts() {

    let searchBar = document.getElementById('search');

    // Get contents of search bar
    let filter = searchBar.value.toUpperCase();

    let postList = document.getElementById('myPosts');
    let posts = postList.getElementsByTagName('article');

    // Loop through all posts, and hide ones that don't match the search
    for (i = 0; i < posts.length; i++) {

        // Search body of post
        let content = posts[i].getElementsByTagName('p')[0];
        let postContent = content.textContent || content.innerText;

        // Search title of post
        let title = posts[i].getElementsByTagName("h3")[0];
        let titleContent = title.textContent || title.innerText;

        // Search username
        let username = posts[i].getElementsByTagName("h5")[0];
        let usernameContent = username.textContent || username.innerText;

        // Change display property of posts depending on whether it matches the search or not
        if (postContent.toUpperCase().indexOf(filter) > -1 || titleContent.toUpperCase().indexOf(filter) > - 1 ||
             usernameContent.toUpperCase().indexOf(filter) > - 1) {
            posts[i].style.display = "";
        } else {
            posts[i].style.display = "none";
        }
    }
}

document.getElementById("search").addEventListener("keyup", searchPosts);

const postForm = document.getElementById('postForm');
const imageInput = document.getElementById('image_files');
const selectedImagesContainer = document.getElementById('selected_images');
const selectedImages = [];
const MAX_SELECTED_IMAGES = 5;
const MAX_IMAGE_SIZE_BYTES = 2 * 1024 * 1024;
const ALLOWED_IMAGE_TYPES = new Set(['image/jpeg', 'image/png', 'image/webp']);

function getFileKey(file) {
    return `${file.name}|${file.size}|${file.lastModified}`;
}

function clearSelectedImages() {
    selectedImages.length = 0;
    renderSelectedImages();
}

function renderSelectedImages() {
    if (!selectedImagesContainer) {
        return;
    }

    selectedImagesContainer.replaceChildren();

    for (const entry of selectedImages) {
        const item = document.createElement('div');
        item.classList.add('selected-image-item');

        const name = document.createElement('div');
        name.classList.add('selected-image-name');
        name.textContent = entry.file.name;
        item.appendChild(name);

        const removeButton = document.createElement('button');
        removeButton.type = 'button';
        removeButton.classList.add('selected-image-remove');
        removeButton.textContent = 'Remove';
        removeButton.addEventListener('click', () => {
            const index = selectedImages.findIndex((img) => img.key === entry.key);
            if (index !== -1) {
                selectedImages.splice(index, 1);
                renderSelectedImages();
            }
        });
        item.appendChild(removeButton);

        selectedImagesContainer.appendChild(item);
    }
}

function addSelectedFiles(fileList) {
    let hadError = false;

    for (const file of fileList) {
        if (!ALLOWED_IMAGE_TYPES.has(file.type)) {
            hadError = true;
            showPostError('Only PNG, JPG, or WEBP images are allowed.');
            continue;
        }

        if (file.size > MAX_IMAGE_SIZE_BYTES) {
            hadError = true;
            showPostError('Each image must be 2MB or smaller.');
            continue;
        }

        if (selectedImages.length >= MAX_SELECTED_IMAGES) {
            hadError = true;
            showPostError(`You can select up to ${MAX_SELECTED_IMAGES} images.`);
            break;
        }

        const key = getFileKey(file);
        if (selectedImages.some((img) => img.key === key)) {
            continue;
        }

        selectedImages.push({
            key,
            file
        });
    }

    if (!hadError) {
        clearPostError();
    }

    renderSelectedImages();
}

if (imageInput) {
    imageInput.addEventListener('change', (event) => {
        addSelectedFiles(event.target.files || []);
        imageInput.value = '';
    });
}

if (postForm) {
    postForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        clearPostError();

        try {
            const formData = new FormData(postForm);
            formData.delete('image_files');

            for (const entry of selectedImages) {
                formData.append('image_files', entry.file);
            }
            // Send the same token in the form body for the server-side CSRF check.
            formData.append('csrf_token', getCookieValue('csrf_token'));
            const response = await fetch('/makepost', {
                method: 'POST',
                headers: {
                    'X-CSRF-Token': getCookieValue('csrf_token')
                },
                body: formData
            });

            if (response.status === 401) {
                window.location.href = '/';
                return;
            }

            if (!response.ok) {
                const message = await response.text();
                showPostError(message || 'Unable to save post.');
                return;
            }

            postForm.reset();
            clearSelectedImages();
            const postIdField = document.getElementById('postId');
            if (postIdField) {
                postIdField.value = '';
            }
            await loadPosts();
        } catch (error) {
            showPostError('Unable to save post. Please try again.');
        }
    });
}

function showPostError(message) {
    const errorEl = document.getElementById('post_error');
    if (!errorEl) {
        return;
    }
    errorEl.textContent = message;
    errorEl.hidden = false;
}

function clearPostError() {
    const errorEl = document.getElementById('post_error');
    if (!errorEl) {
        return;
    }
    errorEl.textContent = '';
    errorEl.hidden = true;
}

// Load and render images for a single post
async function appendPostImages(postId, targetContainer, allowDelete, beforeNode) {
    try {
        const response = await fetch(`/post-images-data?postId=${encodeURIComponent(postId)}`, { cache: 'no-store' });

        if (!response.ok) {
            return;
        }

        const images = await response.json();

        if (!Array.isArray(images) || images.length === 0) {
            return;
        }

        const imageWrap = document.createElement('div');
        imageWrap.classList.add('post-images');

        for (const image of images) {
            const imageItem = document.createElement('div');
            imageItem.classList.add('post-image-item');

            const imageTag = document.createElement('img');
            imageTag.classList.add('post-image');
            imageTag.src = `/post-images/${image.imageId}`;
            imageTag.alt = 'Post image';
            imageItem.appendChild(imageTag);

            if (allowDelete) {
                const deleteButton = document.createElement('button');
                deleteButton.classList.add('image-delete-btn');
                deleteButton.textContent = 'Remove image';
                deleteButton.dataset.imageId = image.imageId;
                deleteButton.addEventListener('click', deleteImage);
                imageItem.appendChild(deleteButton);
            }

            imageWrap.appendChild(imageItem);
        }

        if (beforeNode) {
            targetContainer.insertBefore(imageWrap, beforeNode);
            return;
        }

        targetContainer.appendChild(imageWrap);
    } catch (error) {
        console.error('Failed to load post images:', error);
    }
}

// Remove a single image from the post and update the UI
async function deleteImage(e) {
    const imageId = e.target.dataset.imageId;

    if (!imageId) {
        return;
    }

    try {
        const response = await fetch('/deleteimage', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                // Send the token in a header for JSON requests.
                'X-CSRF-Token': getCookieValue('csrf_token')
            },
            body: JSON.stringify({ imageId })
        });

        if (response.ok) {
            const imageItem = e.target.parentNode;
            imageItem.remove();
        }
    } catch (error) {
        console.error('Failed to delete image:', error);
    }
}
