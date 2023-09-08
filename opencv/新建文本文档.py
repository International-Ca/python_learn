import numpy as np
import cv2 as cv

# mouse callback function
def draw_circle(event,x,y,flags,param):
    if event == cv.EVENT_LBUTTONDBLCLK:
        cv.circle(img,(x,y),100,(255,0,0),-1)

# Create a black image, a window and bind the function to window
img = cv.imread('04.png', 0)
cv.namedWindow('image', 0)
cv.setMouseCallback('image',draw_circle)
while(1):
    cv.imshow('image',img)
    if cv.waitKey(20) & 0xFF == 27:
        break
cv.destroyAllWindows()

# img = cv.imread('04.png',0)
# cv.namedWindow('image',0)
# cv.imshow('image',img)
# k = cv.waitKey(0) & 0xFF
# if k == 27:         # wait for ESC key to exit
#     cv.destroyAllWindows()
# elif k == ord('s'): # wait for 's' key to save and exit
#     cv.imwrite('messigray.png',img)
#     cv.destroyAllWindows()