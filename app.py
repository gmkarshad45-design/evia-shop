<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>{{ product.name }} | EVIA Official</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        body { font-family: 'Inter', sans-serif; background: #ffffff; color: #111; padding-bottom: 90px; margin: 0; }
        
        .back-nav { 
            padding: 12px 15px; border-bottom: 1px solid #eee; 
            display: flex; justify-content: space-between; align-items: center; 
            background: #fff; position: sticky; top: 0; z-index: 1100;
        }

        /* Fixed Horizontal Scroller */
        .scroll-container { position: relative; width: 100%; background: #fff; }
        .scroll-wrapper {
            display: flex; overflow-x: auto; scroll-snap-type: x mandatory;
            scroll-behavior: smooth; -webkit-overflow-scrolling: touch;
        }
        .scroll-wrapper::-webkit-scrollbar { display: none; }
        .scroll-item {
            flex: 0 0 100%; width: 100%; height: 380px;
            scroll-snap-align: start; display: flex; align-items: center; justify-content: center;
        }
        .scroll-item img { max-width: 100%; max-height: 100%; object-fit: contain; }

        .scroll-dots { display: flex; justify-content: center; gap: 6px; padding: 10px 0; }
        .dot { width: 6px; height: 6px; background: #e0e0e0; border-radius: 50%; transition: 0.3s; }
        .dot.active { background: #000; width: 12px; border-radius: 10px; }

        .price-section { font-size: 1.4rem; font-weight: 800; color: #000; margin-top: 5px; }
        .pincode-box { background: #f8f8f8; border-radius: 12px; padding: 15px; border: 1px solid #eee; }
        
        /* Fixed Action Bar for Mobile */
        .bottom-bar {
            position: fixed; bottom: 0; left: 0; right: 0;
            background: #fff; padding: 12px 15px;
            border-top: 1px solid #eee; z-index: 2000;
            display: flex; gap: 10px;
        }
        .cart-btn {
            flex: 1; height: 50px; border-radius: 10px;
            background: #fff; color: #000; border: 2px solid #000;
            font-weight: 800; font-size: 13px;
        }
        .buy-btn-split {
            flex: 1; height: 50px; border-radius: 10px;
            background: #ff9f00; color: #fff; border: none;
            font-weight: 800; font-size: 13px; text-decoration: none;
            display: flex; align-items: center; justify-content: center;
        }

        #cart-toast {
            visibility: hidden; position: fixed; bottom: 100px; left: 50%;
            transform: translateX(-50%); background: #333; color: #fff;
            padding: 12px 25px; border-radius: 50px; z-index: 3000; font-size: 12px;
        }
        #cart-toast.show { visibility: visible; animation: fadeInUp 0.4s; }
        @keyframes fadeInUp { from { opacity: 0; transform: translate(-50%, 20px); } to { opacity: 1; transform: translate(-50%, 0); } }
    </style>
</head>
<body>

    <div class="back-nav">
        <a href="/" class="text-dark"><i class="fa fa-arrow-left"></i></a>
        <span style="font-weight: 800; font-size: 12px;">PRODUCT DETAILS</span>
        <a href="/cart" class="text-dark position-relative">
            <i class="fa fa-shopping-bag" style="font-size: 18px;"></i>
            <span id="cart-count" class="badge rounded-pill bg-danger position-absolute top-0 start-100 translate-middle" style="font-size: 9px;">
                {{ session['cart']|length if session['cart'] else 0 }}
            </span>
        </a>
    </div>

    <div class="scroll-container">
        <div class="scroll-wrapper" id="imageScroller">
            <div class="scroll-item"><img src="{{ product.image }}"></div>
            {% if product.image_2 %}<div class="scroll-item"><img src="{{ product.image_2 }}"></div>{% endif %}
        </div>
        {% if product.image_2 %}
        <div class="scroll-dots">
            <div class="dot active"></div>
            <div class="dot"></div>
        </div>
        {% endif %}
    </div>

    <div class="container p-4">
        <div style="font-size: 10px; color: #888; font-weight: 700;">PREMIUM SURPLUS</div>
        <h1 style="font-weight: 800; font-size: 1.4rem;">{{ product.name }}</h1>
        <div class="price-section">₹{{ product.price }}</div>
        
        <div class="pincode-box mt-3">
            <div style="font-size: 10px; font-weight: 800; color: #666; margin-bottom: 8px;">CHECK DELIVERY</div>
            <div class="d-flex gap-2">
                <input type="number" id="pinInput" class="form-control" placeholder="Pincode" style="font-size: 14px;">
                <button class="btn btn-dark btn-sm px-3" onclick="checkPin()">CHECK</button>
            </div>
            <div id="pinMsg" style="font-size: 11px; margin-top: 8px; font-weight: 600;"></div>
        </div>

        <div class="mt-4">
            <h6 style="font-weight: 800; font-size: 12px;">DESCRIPTION</h6>
            <p style="font-size: 13px; color: #555; line-height: 1.6;">{{ product.description }}</p>
        </div>
    </div>

    <div id="cart-toast">✅ Added to Bag</div>

    <div class="bottom-bar">
        <button class="cart-btn" onclick="addToCart({{ product.id }})">ADD TO CART</button>
        <a href="{{ url_for('buy_now', id=product.id) }}" class="buy-btn-split">BUY NOW</a>
    </div>

    <script>
        function addToCart(pid) {
            fetch('/add_to_cart/' + pid)
                .then(res => res.json())
                .then(data => {
                    if(data.status === 'success') {
                        document.getElementById('cart-count').innerText = data.cart_count;
                        const toast = document.getElementById('cart-toast');
                        toast.classList.add('show');
                        setTimeout(() => toast.classList.remove('show'), 2000);
                    }
                });
        }

        const scroller = document.getElementById('imageScroller');
        const dots = document.querySelectorAll('.dot');
        scroller.addEventListener('scroll', () => {
            const index = Math.round(scroller.scrollLeft / scroller.clientWidth);
            dots.forEach((d, i) => d.classList.toggle('active', i === index));
        });

        function checkPin() {
            const pin = document.getElementById('pinInput').value;
            const msg = document.getElementById('pinMsg');
            if(pin.length === 6) {
                msg.innerText = "✅ Serviceable: Delivery in 5 days";
                msg.style.color = "green";
            } else {
                msg.innerText = "❌ Invalid Pincode";
                msg.style.color = "red";
            }
        }
    </script>
</body>
</html>
